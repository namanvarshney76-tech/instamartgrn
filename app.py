#!/usr/bin/env python3
"""
Combined Streamlit App for Instamart Mail to Drive and PDF to Sheet Workflows
Combines Gmail attachment downloader and LlamaParse PDF processor with real-time tracking
"""

import streamlit as st
import os
import json
import base64
import tempfile
import time
import logging
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from io import StringIO, BytesIO
import threading
import queue
import re
import warnings

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import io

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

warnings.filterwarnings("ignore")

# Configure Streamlit page
st.set_page_config(
    page_title="Instamart Automation Workflows",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hardcoded configuration
CONFIG = {
    'mail': {
        'gdrive_folder_id': '141D679nCRsj3HM9wKhVWyxO9ni7-B6Ws',
        'sender': '',
        'search_term': 'grn & purchase return',
        'attachment_filter': 'GRN'
    },
    'sheet': {
        'llama_api_key': 'llx-csECp5RB25AeiLp57MQ8GnpViLFNyaezTOoHQIiwD7yn0CMr',
        'llama_agent': 'Instamart Agent',
        'drive_folder_id': '19basSTaOUB-X0FlrwmBkeVULgE8nBQ5x',
        'spreadsheet_id': '16WLcJKfkSLkTj1io962aSkgTGbk09PMdJTgkWNn11fw',
        'sheet_range': 'instamartgrn'
    }
}

class InstamartAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        # Initialize logs in session state if not exists
        if 'logs' not in st.session_state:
            st.session_state.logs = []
    
    def log(self, message: str, level: str = "INFO"):
        """Add log entry with timestamp to session state"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp, 
            "level": level.upper(), 
            "message": message
        }
        
        # Add to session state logs
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        
        st.session_state.logs.append(log_entry)
        
        # Keep only last 100 logs to prevent memory issues
        if len(st.session_state.logs) > 100:
            st.session_state.logs = st.session_state.logs[-100:]
    
    def get_logs(self):
        """Get logs from session state"""
        return st.session_state.get('logs', [])
    
    def clear_logs(self):
        """Clear all logs"""
        st.session_state.logs = []
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            self.log("Starting authentication process...", "INFO")
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful using cached token!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful after token refresh!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    self.log(f"Cached token invalid: {str(e)}", "WARNING")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("redirect_uri", "https://instamartgrn.streamlit.app/")
                )
                
                # Generate authorization URL
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                # Check for callback code
                query_params = st.query_params
                if "code" in query_params:
                    try:
                        code = query_params["code"]
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        # Save credentials in session state
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        self.log("OAuth authentication successful!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        self.log(f"OAuth authentication failed: {str(e)}", "ERROR")
                        st.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Click here to authorize with Google]({auth_url})")
                    self.log("Waiting for user to authorize application", "INFO")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                self.log("Google credentials missing in Streamlit secrets", "ERROR")
                st.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            self.log(f"Authentication failed: {str(e)}", "ERROR")
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                     days_back: int = 7, max_results: int = 50) -> List[Dict]:
        """Search for emails with attachments"""
        try:
            # Build search query
            query_parts = ["has:attachment"]
            
            if sender:
                query_parts.append(f'from:"{sender}"')  
            
            if search_term:
                if "," in search_term:
                    keywords = [k.strip() for k in search_term.split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{search_term}"')
            
            # Add date filter
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            self.log(f"[SEARCH] Searching Gmail with query: {query}")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            self.log(f"[SEARCH] Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            self.log(f"[ERROR] Email search failed: {str(e)}")
            return []
    
    def get_email_details(self, message_id: str) -> Dict:
        """Get email details including sender and subject"""
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='metadata'
            ).execute()
            
            headers = message['payload'].get('headers', [])
            
            details = {
                'id': message_id,
                'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
            }
            
            return details
            
        except Exception as e:
            self.log(f"[ERROR] Failed to get email details for {message_id}: {str(e)}")
            return {}
    
    def sanitize_filename(self, filename: str) -> str:
        """Clean up filenames to be safe for all operating systems"""
        cleaned = re.sub(r'[<>:"/\\|?*]', '_', filename)
        if len(cleaned) > 100:
            name_parts = cleaned.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                cleaned = f"{base_name[:95]}.{extension}"
            else:
                cleaned = cleaned[:100]
        return cleaned
    
    def classify_extension(self, filename: str) -> str:
        """Categorize file by extension"""
        if not filename or '.' not in filename:
            return "Other"
            
        ext = filename.split(".")[-1].lower()
        
        type_map = {
            "pdf": "PDFs",
            "doc": "Documents", "docx": "Documents", "txt": "Documents",
            "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
            "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
            "ppt": "Presentations", "pptx": "Presentations",
            "zip": "Archives", "rar": "Archives", "7z": "Archives",
        }
        
        return type_map.get(ext, "Other")
    
    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        """Create a folder in Google Drive"""
        try:
            # First check if folder already exists
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                # Folder already exists, return its ID
                folder_id = files[0]['id']
                self.log(f"[DRIVE] Using existing folder: {folder_name} (ID: {folder_id})")
                return folder_id
            
            # Create new folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            self.log(f"[DRIVE] Created Google Drive folder: {folder_name} (ID: {folder_id})")
            
            return folder_id
            
        except Exception as e:
            self.log(f"[ERROR] Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        """Upload file to Google Drive"""
        try:
            # Check if file already exists
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                self.log(f"[DRIVE] File already exists, skipping: {filename}")
                return True
            
            file_metadata = {
                'name': filename,
                'parents': [folder_id] if folder_id else []
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype='application/octet-stream',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            self.log(f"[DRIVE] Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            self.log(f"[ERROR] Failed to upload {filename}: {str(e)}")
            return False
    
    def process_attachment(self, message_id: str, part: Dict, sender_info: Dict, 
                          search_term: str, base_folder_id: str, attachment_filter: str) -> bool:
        """Process and upload a single attachment"""
        try:
            # Get filename
            filename = part.get("filename", "")
            if not filename:
                return False
            
            # Apply attachment filter
            if attachment_filter and attachment_filter.lower() not in filename.lower():
                self.log(f"[SKIPPED] Attachment {filename} does not contain '{attachment_filter}'")
                return False
            
            # Clean filename
            clean_filename = self.sanitize_filename(filename)
            final_filename = f"{message_id}_{clean_filename}"

            # Get attachment data
            attachment_id = part["body"].get("attachmentId")
            if not attachment_id:
                return False
            
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return False
            
            # Decode file data
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            # Create folder structure in Drive (Gmail_Attachments -> search_term -> file_type)
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = self.classify_extension(filename)
            
            # Create nested folder structure
            search_folder_id = self.create_drive_folder(search_folder_name, base_folder_id)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id)
            
            # Upload file
            success = self.upload_to_drive(file_data, final_filename, type_folder_id)
            
            if success:
                self.log(f"[SUCCESS] Processed attachment: {filename}")
            
            return success
            
        except Exception as e:
            self.log(f"[ERROR] Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}")
            return False
    
    def extract_attachments_from_email(self, message_id: str, payload: Dict, 
                                     sender_info: Dict, search_term: str, 
                                     base_folder_id: str, attachment_filter: str) -> int:
        """Recursively extract all attachments from an email"""
        processed_count = 0
        
        # Process parts if they exist
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.extract_attachments_from_email(
                    message_id, part, sender_info, search_term, base_folder_id, attachment_filter
                )
        
        # Process this part if it's an attachment
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, sender_info, search_term, base_folder_id, attachment_filter):
                processed_count += 1
        
        return processed_count
    
    def process_mail_to_drive_workflow(self, config: dict, progress_callback=None, status_callback=None):
        """Process Mail to Drive workflow"""
        try:
            if status_callback:
                status_callback("Starting Mail to Drive workflow...")
            
            self.log("[START] Starting Gmail to Google Drive automation")
            
            # Search for emails
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            
            if progress_callback:
                progress_callback(25)
            
            if not emails:
                self.log("[INFO] No emails found matching criteria")
                return {'success': True, 'processed': 0, 'total_attachments': 0}
            
            if status_callback:
                status_callback(f"Found {len(emails)} emails. Processing attachments...")
            
            # Create base folder in Drive
            base_folder_name = f"Gmail_Attachments"
            base_folder_id = self.create_drive_folder(base_folder_name, config.get('gdrive_folder_id'))
            if not base_folder_id:
                self.log("[ERROR] Failed to create base folder in Google Drive")
                return {'success': False, 'processed': 0, 'total_attachments': 0}
            
            if progress_callback:
                progress_callback(50)
            
            stats = {
                'total_emails': len(emails),
                'processed_emails': 0,
                'total_attachments': 0,
                'successful_uploads': 0,
                'failed_uploads': 0
            }
            
            self.log(f"[PROCESS] Processing {len(emails)} emails...")
            
            for i, email in enumerate(emails, 1):
                try:
                    if status_callback:
                        status_callback(f"Processing email {i}/{len(emails)}")
                    
                    sender_info = self.get_email_details(email['id'])
                    if not sender_info:
                        continue
                    
                    # Get full message
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id']
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        continue
                    
                    # Extract attachments
                    attachment_count = self.extract_attachments_from_email(
                        email['id'], message['payload'], sender_info, config['search_term'], base_folder_id, config['attachment_filter']
                    )
                    
                    stats['total_attachments'] += attachment_count
                    stats['successful_uploads'] += attachment_count
                    stats['processed_emails'] += 1
                    
                    subject = sender_info.get('subject', 'No Subject')[:50]
                    self.log(f"[PROCESS] Found {attachment_count} attachments in email: {subject}")
                    
                    if progress_callback:
                        progress = 50 + (i / len(emails)) * 45
                        progress_callback(int(progress))
                    
                except Exception as e:
                    self.log(f"[ERROR] Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                    stats['failed_uploads'] += 1
            
            if progress_callback:
                progress_callback(100)
            
            if status_callback:
                status_callback(f"Mail to Drive workflow completed! Processed {stats['total_attachments']} attachments")
            
            self.log("[COMPLETE] AUTOMATION COMPLETE!")
            self.log(f"[STATS] Emails processed: {stats['processed_emails']}/{stats['total_emails']}")
            self.log(f"[STATS] Total attachments: {stats['total_attachments']}")
            self.log(f"[STATS] Successful uploads: {stats['successful_uploads']}")
            self.log(f"[STATS] Failed uploads: {stats['failed_uploads']}")
            
            return {'success': True, 'processed': stats['processed_emails'], 'total_attachments': stats['total_attachments']}
            
        except Exception as e:
            self.log(f"Mail to Drive workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0, 'total_attachments': 0}
    
    def list_drive_files(self, folder_id: str, days_back: int = 1) -> List[Dict]:
        """List all PDF files in a Google Drive folder filtered by creation date"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back - 1)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            
            files = []
            page_token = None

            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)",
                    orderBy="createdTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken', None)
                
                if page_token is None:
                    break

            self.log(f"[DRIVE] Found {len(files)} PDF files in folder {folder_id} (last {days_back} days)")
            
            return files
        except Exception as e:
            self.log(f"[ERROR] Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            return file_data
        except Exception as e:
            self.log(f"[ERROR] Failed to download file {file_name}: {str(e)}")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]) -> bool:
        """Append data to a Google Sheet with retry mechanism"""
        max_retries = 3
        wait_time = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                self.log(f"[SHEETS] Appended {updated_cells} cells to Google Sheet")
                return True
            except Exception as e:
                if attempt < max_retries:
                    self.log(f"[SHEETS] Attempt {attempt} failed: {str(e)}")
                    time.sleep(wait_time)
                else:
                    self.log(f"[ERROR] Failed to append to Google Sheet: {str(e)}")
                    return False
        return False
    
    def get_sheet_headers(self, spreadsheet_id: str, sheet_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1",
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            self.log(f"[SHEETS] No existing headers or error: {str(e)}")
            return []
    
    def get_value(self, data, possible_keys, default=""):
        """Return the first found key value from dict."""
        for key in possible_keys:
            if key in data:
                return data[key]
        return default
    
    def safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        """Retry-safe extraction to handle server disconnections"""
        for attempt in range(1, retries + 1):
            try:
                result = agent.extract(file_path)
                return result
            except Exception as e:
                self.log(f"Attempt {attempt} failed for {file_path}: {e}")
                time.sleep(wait_time)
        raise Exception(f"Extraction failed after {retries} attempts for {file_path}")
    
    def process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """
        Process extracted data to match the specified JSON structure
        Returns a list of dictionaries (rows) for Google Sheets
        """
        rows = []
        items = []
        if "items" in extracted_data or "product_items" in extracted_data:
            items = extracted_data.get("items", extracted_data.get("product_items", []))
            
            # Define top-level fields
            row_base = {
                "vendor_name": self.get_value(extracted_data, ["vendor_name", "supplier", "vendor", "Supplier Name"]),
                "po_number": self.get_value(extracted_data, ["po_number", "purchase_order_number", "PO No"]),
                "po_date": self.get_value(extracted_data, ["po_date", "purchase_order_date"]),
                "grn_no": self.get_value(extracted_data, ["grn_no", "grn_number"]),
                "grn_date": self.get_value(extracted_data, ["grn_date", "delivered_on", "GRN Date"]),
                "invoice_no": self.get_value(extracted_data, ["invoice_no", "vendor_invoice_number", "invoice_number", "inv_no", "Invoice No"]),
                "invoice_date": self.get_value(extracted_data, ["invoice_date", "invoice_dt"]),
                "source_file": file_info['name'],
                "processed_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "drive_file_id": file_info['id']
            }
            
            for item in items:
                row = row_base.copy()
                row.update({
                    "sku_code": self.get_value(item, ["sku_code", "sku"]),
                    "sku_description": self.get_value(item, ["sku_description", "description", "product_name"]),
                    "vendor_sku": self.get_value(item, ["vendor_sku", "vendor_sku_code"]),
                    "sku_bin": self.get_value(item, ["sku_bin", "bin_code"]),
                    "lot_no": self.get_value(item, ["lot_no", "lot_number"]),
                    "lot_mrp": self.get_value(item, ["lot_mrp", "mrp"]),
                    "exp_qty": self.get_value(item, ["exp_qty", "expected_quantity"]),
                    "recv_qty": self.get_value(item, ["recv_qty", "received_quantity"]),
                    "unit_price": self.get_value(item, ["unit_price", "price_per_unit"]),
                    "taxable_value": self.get_value(item, ["taxable_value", "taxable_amt"]),
                    "add_cess": self.get_value(item, ["add_cess", "additional_cess"]),
                    "total_inr": self.get_value(item, ["total_inr", "total_amount"])
                })
                cleaned_row = {k: v for k, v in row.items() if v not in ["", None]}
                rows.append(cleaned_row)
        else:
            self.log(f"Skipping (no recognizable items key): {file_info['name']}")
            return rows
        
        return rows
    
    def get_existing_drive_ids(self, spreadsheet_id: str, sheet_range: str) -> set:
        """Get set of existing drive_file_id from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if not values:
                return set()
            
            headers = values[0]
            if "drive_file_id" not in headers:
                self.log("No 'drive_file_id' column found in sheet", "WARNING")
                return set()
            
            id_index = headers.index("drive_file_id")
            existing_ids = {row[id_index] for row in values[1:] if len(row) > id_index and row[id_index]}
            
            self.log(f"Found {len(existing_ids)} existing file IDs in sheet", "INFO")
            return existing_ids
            
        except Exception as e:
            self.log(f"Failed to get existing file IDs: {str(e)}", "ERROR")
            return set()
    
    def update_headers(self, spreadsheet_id: str, sheet_name: str, new_headers: List[str]) -> bool:
        """Update the header row with new columns"""
        try:
            body = {'values': [new_headers]}
            result = self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:{chr(64 + len(new_headers))}1",
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            self.log(f"Updated headers with {len(new_headers)} columns")
            return True
        except Exception as e:
            self.log(f"[ERROR] Failed to update headers: {str(e)}")
            return False
    
    def process_drive_to_sheet_workflow(self, config: dict, progress_callback=None, status_callback=None, skip_existing: bool = False, max_files: Optional[int] = None):
        """Process Drive to Sheet workflow"""
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            self.log("[ERROR] LlamaParse not available. Install with: pip install llama-cloud-services")
            return stats
        
        try:
            if status_callback:
                status_callback("Starting Drive to Sheet workflow...")
            
            self.log("Starting Drive to Sheet workflow with LlamaParse", "INFO")
            
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                self.log(f"[ERROR] Could not find agent '{config['llama_agent']}'. Check dashboard.")
                return stats
            
            self.log("LlamaParse agent found")
            
            sheet_name = config['sheet_range'].split('!')[0]
            
            # Get existing IDs if skipping
            existing_ids = set()
            if skip_existing:
                existing_ids = self.get_existing_drive_ids(config['spreadsheet_id'], config['sheet_range'])
                self.log(f"Skipping {len(existing_ids)} already processed files", "INFO")
            
            pdf_files = self.list_drive_files(config['drive_folder_id'], config['days_back'])
            stats['total_pdfs'] = len(pdf_files)
            
            if skip_existing:
                pdf_files = [f for f in pdf_files if f['id'] not in existing_ids]
                self.log(f"After filtering, {len(pdf_files)} PDFs to process", "INFO")
            
            if max_files is not None:
                pdf_files = pdf_files[:max_files]
                self.log(f"Limited to {len(pdf_files)} PDFs after max_files limit", "INFO")
            
            if progress_callback:
                progress_callback(25)
            
            if not pdf_files:
                self.log("[INFO] No PDF files found in the specified folder")
                return stats
            
            if status_callback:
                status_callback(f"Found {len(pdf_files)} PDF files. Processing...")
            
            self.log(f"📊 Found {len(pdf_files)} PDF files to process")
            
            # Get initial headers
            headers = self.get_sheet_headers(config['spreadsheet_id'], sheet_name)
            headers_set = False
            
            for i, file in enumerate(pdf_files, 1):
                try:
                    if status_callback:
                        status_callback(f"Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    self.log(f"[LLAMA] Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    if not pdf_data:
                        self.log(f"[ERROR] Failed to download PDF: {file['name']}")
                        stats['failed_pdfs'] += 1
                        continue
                    
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    result = self.safe_extract(agent, temp_path)
                    extracted_data = result.data
                    os.unlink(temp_path)
                    
                    rows = self.process_extracted_data(extracted_data, file)
                    if not rows:
                        self.log(f"No rows extracted from: {file['name']}")
                        continue
                    
                    stats['processed_pdfs'] += 1
                    self.log(f"Successfully processed: {file['name']}")
                    self.log(f"Extracted {len(rows)} rows from this PDF")
                    
                    # Set headers from first file if none exist
                    if not headers and not headers_set:
                        headers = list(set().union(*(row.keys() for row in rows)))
                        self.update_headers(config['spreadsheet_id'], sheet_name, headers)
                        headers_set = True
                    
                    # Prepare values using established headers
                    values = [[row.get(h, "") for h in headers] for row in rows]
                    
                    # Append to sheet
                    success = self.append_to_google_sheet(
                        spreadsheet_id=config['spreadsheet_id'],
                        range_name=config['sheet_range'],
                        values=values
                    )
                    
                    if success:
                        stats['rows_added'] += len(rows)
                        self.log(f"Successfully saved {len(rows)} rows for this PDF")
                    else:
                        self.log(f"Failed to save rows for {file['name']}")
                        stats['failed_pdfs'] += 1
                    
                    if progress_callback:
                        progress = 25 + (i / len(pdf_files)) * 70
                        progress_callback(int(progress))
                    
                except Exception as e:
                    self.log(f"[ERROR] Failed to process PDF {file['name']}: {str(e)}")
                    stats['failed_pdfs'] += 1
            
            if progress_callback:
                progress_callback(100)
            
            if status_callback:
                status_callback(f"Drive to Sheet workflow completed! Processed {stats['processed_pdfs']} PDFs, added {stats['rows_added']} rows")
            
            return stats
        except Exception as e:
            self.log(f"[ERROR] LlamaParse processing failed: {str(e)}")
            return stats

def main():
    """Main Streamlit application"""
    st.title("🤖 Instamart Automation Workflows")
    st.markdown("### Mail to Drive & Drive to Sheet Processing")
    
    # Initialize automation instance in session state
    if 'automation' not in st.session_state:
        st.session_state.automation = InstamartAutomation()
    
    # Initialize workflow running state
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    
    automation = st.session_state.automation
    
    # Sidebar configuration
    st.sidebar.header("Configuration")
    
    # Authentication section
    st.sidebar.subheader("🔐 Authentication")
    auth_status = st.sidebar.empty()
    
    if not automation.gmail_service or not automation.drive_service:
        if st.sidebar.button("🚀 Authenticate with Google", type="primary"):
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            
            success = automation.authenticate_from_secrets(progress_bar, status_text)
            if success:
                auth_status.success("✅ Authenticated successfully!")
                st.sidebar.success("Ready to process workflows!")
            else:
                auth_status.error("❌ Authentication failed")
            
            progress_bar.empty()
            status_text.empty()
    else:
        auth_status.success("✅ Already authenticated")
        
        # Clear authentication button
        if st.sidebar.button("🔄 Re-authenticate"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.automation = InstamartAutomation()
            st.rerun()
    
    # Main tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📧 Mail to Drive", "📄 Drive to Sheet", "🔗 Combined Workflow", "📋 Logs & Status"])
    
    # Tab 1: Mail to Drive Workflow
    with tab1:
        st.header("📧 Mail to Drive Processor")
        st.markdown("Download attachments from Gmail and organize them in Google Drive")
        
        if not automation.gmail_service or not automation.drive_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("Sender Email", value=CONFIG['mail']['sender'], disabled=True, key="mail_sender")
                st.text_input("Search Keywords", value=CONFIG['mail']['search_term'], disabled=True, key="mail_search_term")
                st.text_input("Google Drive Folder ID", value=CONFIG['mail']['gdrive_folder_id'], disabled=True, key="mail_drive_folder")
                st.text_input("Attachment Filter", value=CONFIG['mail']['attachment_filter'], disabled=True, key="mail_attachment_filter")
                
                st.subheader("Search Parameters")
                mail_days_back = st.number_input(
                    "Days to search back", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="How many days back to search",
                    key="mail_days_back"
                )
                mail_max_results = st.number_input(
                    "Maximum emails to process", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum number of emails to process",
                    key="mail_max_results"
                )
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Searches Gmail for emails with attachments\n"
                       "2. Creates organized folder structure in Drive\n"
                       "3. Downloads and saves attachments by type\n"
                       "4. Avoids duplicates automatically")
            
            # Mail workflow execution
            if st.button("🚀 Start Mail to Drive Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_mail_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        config = {
                            'sender': CONFIG['mail']['sender'],
                            'search_term': CONFIG['mail']['search_term'],
                            'days_back': mail_days_back,
                            'max_results': mail_max_results,
                            'gdrive_folder_id': CONFIG['mail']['gdrive_folder_id'],
                            'attachment_filter': CONFIG['mail']['attachment_filter']
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            result = automation.process_mail_to_drive_workflow(
                                config, 
                                progress_callback=update_progress,
                                status_callback=update_status
                            )
                            
                            if result['success']:
                                st.success(f"✅ Mail to Drive workflow completed successfully! Processed {result['total_attachments']} attachments.")
                            else:
                                st.error("❌ Mail to Drive workflow failed. Check logs for details.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 2: Drive to Sheet Workflow
    with tab2:
        st.header("📄 Drive to Sheet Processor")
        st.markdown("Extract structured data from PDFs using LlamaParse and save to Google Sheets")
        
        if not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Please install: `pip install llama-cloud-services`")
        elif not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("LlamaParse API Key", value="***HIDDEN***", disabled=True, key="sheet_api_key")
                st.text_input("LlamaParse Agent Name", value=CONFIG['sheet']['llama_agent'], disabled=True, key="sheet_agent_name")
                st.text_input("PDF Source Folder ID", value=CONFIG['sheet']['drive_folder_id'], disabled=True, key="sheet_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['sheet']['spreadsheet_id'], disabled=True, key="sheet_spreadsheet_id")
                st.text_input("Sheet Range", value=CONFIG['sheet']['sheet_range'], disabled=True, key="sheet_sheet_range")
                
                st.subheader("Processing Parameters")
                sheet_days_back = st.number_input(
                    "Process PDFs from last N days", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="Only process PDFs created in the last N days",
                    key="sheet_days_back"
                )
                sheet_max_files = st.number_input(
                    "Maximum PDFs to process", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum number of PDFs to process",
                    key="sheet_max_files"
                )
                sheet_skip_existing = st.checkbox("Skip already processed files", value=True, key="sheet_skip_existing")
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Finds PDFs in specified Drive folder\n"
                       "2. Processes each PDF with LlamaParse\n"
                       "3. Extracts structured data\n"
                       "4. Appends results to Google Sheets")
            
            # Sheet workflow execution
            if st.button("🚀 Start Drive to Sheet Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_sheet_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        config = {
                            'llama_api_key': CONFIG['sheet']['llama_api_key'],
                            'llama_agent': CONFIG['sheet']['llama_agent'],
                            'drive_folder_id': CONFIG['sheet']['drive_folder_id'],
                            'spreadsheet_id': CONFIG['sheet']['spreadsheet_id'],
                            'sheet_range': CONFIG['sheet']['sheet_range'],
                            'days_back': sheet_days_back
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            result = automation.process_drive_to_sheet_workflow(
                                config, 
                                progress_callback=update_progress,
                                status_callback=update_status,
                                skip_existing=sheet_skip_existing,
                                max_files=sheet_max_files
                            )
                            
                            if result['total_pdfs'] > 0:
                                st.success(f"✅ Drive to Sheet workflow completed successfully! Processed {result['processed_pdfs']} PDFs, added {result['rows_added']} rows.")
                            else:
                                st.info("No PDFs processed.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 3: Combined Workflow
    with tab3:
        st.header("🔗 Combined Workflow")
        st.markdown("Run both Mail to Drive and Drive to Sheet workflows sequentially")
        
        if not automation.gmail_service or not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        elif not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Please install: `pip install llama-cloud-services`")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("Mail Sender", value=CONFIG['mail']['sender'], disabled=True, key="combined_mail_sender")
                st.text_input("Mail Search Keywords", value=CONFIG['mail']['search_term'], disabled=True, key="combined_mail_search_term")
                st.text_input("Mail Drive Folder ID", value=CONFIG['mail']['gdrive_folder_id'], disabled=True, key="combined_mail_drive_folder")
                st.text_input("Sheet LlamaParse API Key", value="***HIDDEN***", disabled=True, key="combined_sheet_api_key")
                st.text_input("Sheet LlamaParse Agent Name", value=CONFIG['sheet']['llama_agent'], disabled=True, key="combined_sheet_agent_name")
                st.text_input("Sheet PDF Source Folder ID", value=CONFIG['sheet']['drive_folder_id'], disabled=True, key="combined_sheet_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['sheet']['spreadsheet_id'], disabled=True, key="combined_sheet_spreadsheet_id")
                st.text_input("Sheet Range", value=CONFIG['sheet']['sheet_range'], disabled=True, key="combined_sheet_sheet_range")
                
                st.subheader("Parameters")
                combined_days_back = st.number_input(
                    "Days back for both workflows", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="Days back for Mail search and PDF processing",
                    key="combined_days_back"
                )
                combined_max_emails = st.number_input(
                    "Max emails for Mail", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum emails to process in Mail workflow",
                    key="combined_max_emails"
                )
                combined_max_files = st.number_input(
                    "Max PDFs for processing", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum number of PDFs to process",
                    key="combined_max_files"
                )
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Run Mail to Drive first\n"
                       "2. Check existing processed PDFs in sheet\n"
                       "3. Run Drive to Sheet only on new files\n"
                       "4. Show combined summary")
            
            # Combined workflow execution
            if st.button("🚀 Start Combined Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_combined_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        mail_config = {
                            'sender': CONFIG['mail']['sender'],
                            'search_term': CONFIG['mail']['search_term'],
                            'days_back': combined_days_back,
                            'max_results': combined_max_emails,
                            'gdrive_folder_id': CONFIG['mail']['gdrive_folder_id'],
                            'attachment_filter': CONFIG['mail']['attachment_filter']
                        }
                        
                        sheet_config = {
                            'llama_api_key': CONFIG['sheet']['llama_api_key'],
                            'llama_agent': CONFIG['sheet']['llama_agent'],
                            'drive_folder_id': CONFIG['sheet']['drive_folder_id'],
                            'spreadsheet_id': CONFIG['sheet']['spreadsheet_id'],
                            'sheet_range': CONFIG['sheet']['sheet_range'],
                            'days_back': combined_days_back,
                            'max_files': combined_max_files
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            # Run Mail to Drive workflow
                            update_status("Running Mail to Drive...")
                            mail_result = automation.process_mail_to_drive_workflow(
                                mail_config, 
                                progress_callback=update_progress,
                                status_callback=update_status
                            )
                            
                            if not mail_result['success']:
                                st.error("❌ Mail to Drive workflow failed. Stopping combined workflow.")
                                return
                            
                            # Run Drive to Sheet workflow with skip_existing
                            update_status("Checking existing files and running Drive to Sheet...")
                            sheet_result = automation.process_drive_to_sheet_workflow(
                                sheet_config, 
                                progress_callback=update_progress,
                                status_callback=update_status,
                                skip_existing=True
                            )
                            
                            st.success(f"✅ Combined workflow completed! Mail: Processed {mail_result['total_attachments']} attachments. Sheet: Processed {sheet_result['processed_pdfs']} new PDFs, added {sheet_result['rows_added']} rows.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 4: Logs and Status
    with tab4:
        st.header("📋 System Logs & Status")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Logs", key="refresh_logs"):
                st.rerun()
        with col2:
            if st.button("🗑️ Clear Logs", key="clear_logs"):
                automation.clear_logs()
                st.success("Logs cleared!")
                st.rerun()
        with col3:
            if st.checkbox("Auto-refresh (5s)", value=False, key="auto_refresh_logs"):
                time.sleep(5)
                st.rerun()
        
        # Display logs
        logs = automation.get_logs()
        
        if logs:
            st.subheader(f"Recent Activity ({len(logs)} entries)")
            
            # Show logs in reverse chronological order (newest first)
            for log_entry in reversed(logs[-50:]):  # Show last 50 logs
                timestamp = log_entry['timestamp']
                level = log_entry['level']
                message = log_entry['message']
                
                # Color coding based on log level
                if level == "ERROR":
                    st.error(f"🔴 **{timestamp}** - {message}")
                elif level == "WARNING":
                    st.warning(f"🟡 **{timestamp}** - {message}")
                elif level == "SUCCESS":
                    st.success(f"🟢 **{timestamp}** - {message}")
                else:  # INFO
                    st.info(f"ℹ️ **{timestamp}** - {message}")
        else:
            st.info("No logs available. Start a workflow to see activity logs here.")
        
        # System status
        st.subheader("🔧 System Status")
        status_cols = st.columns(2)
        
        with status_cols[0]:
            st.metric("Authentication Status", 
                     "✅ Connected" if automation.gmail_service else "❌ Not Connected")
            st.metric("Workflow Status", 
                     "🟡 Running" if st.session_state.workflow_running else "🟢 Idle")
        
        with status_cols[1]:
            st.metric("LlamaParse Available", 
                     "✅ Available" if LLAMA_AVAILABLE else "❌ Not Installed")
            st.metric("Total Logs", len(logs))


# Run the application
if __name__ == "__main__":
    main()
