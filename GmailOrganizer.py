import os.path
from base64 import urlsafe_b64decode
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re
import time

# If modifying these scopes, delete the file token.json.
# This basically tells the code what it can do with the email data of the authorized user
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


# Global Variables-----------------------------
global num_emails
# ---------------------------------------------





# Main------------------------------------------------------------------------------
def main():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.

    # Credentials Code----------------------------------------------------------
    # This block basically determines the email account the code will get data from
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    # -------------------------------------------------------------------------

    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)
        get_user_profile(service)
        show_menu(service)


    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f"An error occurred: {error}")
# ----------------------------------------------------------------------------------





# Functions to do various mailbox things--------------------------------------
def get_user_profile(service):
    try:
        # Call Gmail API to get user profile
        profile = service.users().getProfile(userId="me").execute()
        print("User Profile:")
        print(f"\tEmail Address: {profile['emailAddress']}")
        print(f"\tMessages Total: {profile['messagesTotal']}\n\n")
    except HttpError as error:
        print(f"An error occurred while retrieving user profile: {error}")

def get_user_emails(service, num_emails):
    try:
        results = service.users().messages().list(userId="me").execute()
        messages = results.get("messages", [])[:num_emails]

        for message in messages:
            message_id = message["id"]
            full_message = get_user_email_details(message_id, service)

            print("\nStart of email-------------------------------------")
            # Retrieve sender information
            sender = get_sender(full_message)
            if sender:
                print(f"From: {sender}")
            print(f"Message ID: {message_id}")
            print(f"{full_message['labelIds']}")

            # Iterate through message parts (for multipart messages)
            for part in full_message["payload"].get("parts", [full_message["payload"]]):
                body = decode_message_part(part)
                if body:
                    print(f"Body:\n{body}")
            print("\nEnd of email-------------------------------------\n\n")
            print(f"---- 1) Trash message ---- 2) Add label(s) to message ---- 3) Remove label(s) ---- 4) Next message ---- 5) Exit Search ----\n")
            menu_choice = input(f"Enter menu choice: ")
            if menu_choice == "1":
                trash_message(message_id, service)
            elif menu_choice == "2":
                add_labels_to_message(message_id, service)
            elif menu_choice == "3":
                remove_labels_from_message(message_id, service)
            elif menu_choice == "4":
                continue
            else:
                break
            
    except HttpError as error:
        print(f"An error occurred while retrieving user profile: {error}")
        
def trash_messages_by_sender(service, sender_email):
    try:
        query = f"from:{sender_email}"
        response = service.users().messages().list(userId="me", q=query, maxResults=100).execute()
        while 'messages' in response:
            print(f"Searching current batch of emails for {sender_email}")
            trash_sender_messages(response['messages'], service, sender_email)
            if 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = service.users().messages().list(userId="me", q=query, pageToken=page_token, maxResults=100).execute()
            else:
                break

    except HttpError as error:
        print(f"An error occurred while trashing emails: {error}")
def trash_sender_messages(messages, service, sender_email):
    for message in messages:
        message_id = message["id"]
        full_message = get_user_email_details(message_id, service)
        sender = get_sender(full_message)
        if sender == sender_email:
            print(f"Trashing message from {sender}")
            service.users().messages().trash(userId="me", id=message_id).execute()
# -----------------------------------------------------------------------------





# Search Function-----------------------------------------------------
def search_emails(service, search_query):
    try:
        response = service.users().messages().list(userId="me", q=search_query).execute()
        messages = response.get("messages", [])
        for message in messages:
            message_id = message["id"]
            full_message = get_user_email_details(message_id, service)
            print("\nStart of email-------------------------------------")
            sender = get_sender(full_message)
            if sender:
                print(f"From: {sender}")
            print(f"Message ID: {message_id}")
            print(f"{full_message['labelIds']}")
            for part in full_message["payload"].get("parts", [full_message["payload"]]):
                body = decode_message_part(part)
                if body:
                    print(f"Body:\n{body}")
            print("\nEnd of email-------------------------------------\n")
            print(f"---- 1) Trash message ---- 2) Add label(s) to message ---- 3) Remove label(s) ---- 4) Next message ---- 5) Exit Search ----\n")
            menu_choice = input(f"Enter menu choice: ")
            if menu_choice == "1":
                trash_message(message_id, service)
            elif menu_choice == "2":
                add_labels_to_message(message_id, service)
            elif menu_choice == "3":
                remove_labels_from_message(message_id, service)
            elif menu_choice == "4":
                continue
            else:
                break
            
    except HttpError as error:
        print(f"An error occurred while searching emails: {error}")
# --------------------------------------------------------------------





# Functions to get different parts of an email--------------------------------------------
def get_user_email_details(message_id, service):
    message = service.users().messages().get(userId="me", id=message_id).execute()
    return message

def get_message_body(message):
    try:
        # Check if the message has multiple parts (multipart)
        if "parts" in message["payload"]:
            for part in message["payload"]["parts"]:
                if part["mimeType"] == "text/plain":
                    return part["body"].get("data", "")
        # If the message is single-part (plain text or HTML)
        return message["payload"]["body"].get("data", "")

    except KeyError:
        return None

def get_sender(message):
    headers = message["payload"]["headers"]
    for header in headers:
        if header["name"] == "From":
            from_value = header["value"]
            # Use regex to extract email address
            email_match = re.search(r'<(.+?)>', from_value)
            if email_match :
                # Extract and return the email address within angle brackets
                return email_match.group(1)
            else :
                # If the email is not in angle brackets, return the full value
                return from_value
    return None
# ----------------------------------------------------------------------------------------





# Label Functions----------------------------------------------------------
def add_labels_to_message(message_id, service):
    get_mailbox_labels(service)
    labels = []
    while True:
        label = input(f"Enter label to add to message: ")
        labels.append(label)
        
        choice = input(f"Add another label (Y/N)?: ")
        if choice == "Y":
            continue
        elif choice == "N":
            service.users().messages().modify(userId="me", id=message_id, body={'addLabelIds': labels}).execute()
            break
    print(f"Label(s) successfully added to message!\n")
    time.sleep(3)
    
def remove_labels_from_message(message_id, service):
    get_mailbox_labels(service)
    labels = []
    while True:
        label = input(f"Enter label to remove from message: ")
        labels.append(label)
        
        choice = input(f"Choose another label to remove (Y/N)?: ")
        if choice == "Y":
            continue
        elif choice == "N":
            service.users().messages().modify(userId="me", id=message_id, body={'removeLabelIds': labels}).execute()
            break
    print(f"Label(s) successfully removed from message!\n")
    time.sleep(3)
    
# -------------------------------------------------------------------------





# Decoder functions------------------------------------------
# These functions take data from the email messages and decodes them to make them reable text
def decode_message_part(part):
    content_type = part.get("mimeType", "")
    body = part.get("body", {}).get("data", "")

    if content_type == "text/plain":
        return base64url_decode(body)
    elif content_type == "text/html":
        return html_decode(body)
    else:
        return ""

def base64url_decode(data):
    try:
        byte_string = urlsafe_b64decode(data)
        return byte_string.decode("utf-8")
    except Exception as e:
        print(f"Error decoding base64url: {e}")
        return ""

def html_decode(data):
    try:
        byte_string = urlsafe_b64decode(data)
        html_content = byte_string.decode("utf-8")
        soup = BeautifulSoup(html_content, "html.parser")
        # Get text content and normalize whitespace
        plain_text = " ".join(soup.stripped_strings)
        return plain_text
    except Exception as e:
        print(f"Error decoding HTML: {e}")
        return ""
# -----------------------------------------------------------





# Helper Functions--------------------------------------------
def get_number_of_emails(service):
    global num_emails 
    num_emails = input("Enter number of emails to fetch: ")
    
    # Convert input to integer
    num_emails = int(num_emails)
    
    get_user_emails(service, num_emails)
    
def trash_message(message_id, service):
    service.users().messages().trash(userId="me", id=message_id).execute()
    print("Successfully trashed message")
    
def get_mailbox_labels(service):
    response = service.users().labels().list(userId = "me").execute()
    labels = response.get("labels", [])
    print(f"---------- Labels ----------")
    for label in labels:
        print(label["name"])
    print(f"----------------------------\n")
    time.sleep(2)
    
def show_menu(service):
    while True :
        print(f"---------- Main Menu ----------")
        print(f"| 1) Show some emails         |")
        print(f"| 2) Trash emails by sender   |")
        print(f"| 3) Search emails            |")
        print(f"| 4) Get mailbox labels       |")
        print(f"| 5) Quit                     |")
        print(f"-------------------------------\n")
        menu_choice = input("Enter menu choice: ")
    
        if menu_choice == "1":
            get_number_of_emails(service)
        elif menu_choice == "2":
            print(f'\nFor the sender value, input JUST the email address!\n')
            sender_email = input(f"Enter sender you'd like to trash emails from: ")
            trash_messages_by_sender(service, sender_email)
            print(f"Done!")
        elif menu_choice == "3":
            search_query = input(f"\nEnter search query: ")
            search_emails(service, search_query)
        elif menu_choice == "4":
            get_mailbox_labels(service)
        elif menu_choice == "5":
            print(f"\nThank you! Bye-bye!")
            break
        else:
            print(f"Invalid menu choice. Try again.\n")
# ------------------------------------------------------------





if __name__ == "__main__":
    main()