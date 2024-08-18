import socket
import requests
import ssl
import tkinter as tk
from tkinter import ttk
from bs4 import BeautifulSoup
import whois
import unittest
from unittest.mock import patch


class WebInfoGUI:
    def __init__(self, master):
        self.master = master
        master.title("Web Information Retrieval Tool")
        master.configure(bg="#f0f0f0")

        # Entry and Button Frame
        entry_frame = tk.Frame(master, bg="#f0f0f0", padx=10, pady=10)
        entry_frame.pack()

        self.label = tk.Label(entry_frame, text="Enter URL:", bg="#f0f0f0", fg="#333333", font=("Helvetica", 12))
        self.label.grid(row=0, column=0, sticky="w", padx=5)

        self.entry = tk.Entry(entry_frame, width=30, bg="white", fg="#333333", bd=2, relief="solid")
        self.entry.grid(row=0, column=1, padx=5)

        self.button = tk.Button(entry_frame, text="Get Information", command=self.retrieve_info, bg="#4CAF50", fg="white", font=("Helvetica", 10), padx=10)
        self.button.grid(row=0, column=2, padx=5)

        self.clear_button = tk.Button(entry_frame, text="Clear", command=self.clear_output, bg="#f44336", fg="white", font=("Helvetica", 10), padx=10)
        self.clear_button.grid(row=0, column=3, padx=5)

        self.quit_button = tk.Button(entry_frame, text="Quit", command=master.destroy, bg="#333333", fg="white", font=("Helvetica", 10), padx=10)
        self.quit_button.grid(row=0, column=4)

        # Text Area
        self.text_area = tk.Text(master, wrap=tk.WORD, width=80, height=20, bg="white", fg="#333333", padx=10, pady=10, font=("Courier New", 10), bd=2, relief="solid")
        self.text_area.pack()

    def retrieve_info(self):
        url = self.entry.get()
        self.text_area.insert(tk.END, f"Retrieving information for {url}\n")

        # Retrieve website status
        website_status = WebsiteStatus(url)
        status_code = website_status.get_website_status()
        self.text_area.insert(tk.END, f"Website status code: {status_code}\n")

        # Retrieve server information
        url_info_retriever = UrlInfoRetriever()
        server_info = url_info_retriever.get_server_info(url)
        self.text_area.insert(tk.END, f"Server information: {server_info}\n")

        # Retrieve WHOIS information
        whois_info = url_info_retriever.get_whois_info(url)
        self.text_area.insert(tk.END, f"WHOIS information: {whois_info}\n")

        # Retrieve subdomains
        subdomain_retriever = SubdomainRetriever()
        subdomains = subdomain_retriever.get_all_subdomains(url)
        self.text_area.insert(tk.END, f"Subdomains: {', '.join(subdomains)}\n")

        # Retrieve webpage content type
        web_page_info = WebPageInfo(url)
        content_type = web_page_info.get_content_type()
        self.text_area.insert(tk.END, f"Content type: {content_type}\n")

        # Retrieve webpage metadata
        metadata_types = web_page_info.get_metadata_type()
        self.text_area.insert(tk.END, f"Metadata types: {', '.join(metadata_types)}\n")

    def clear_output(self):
        self.text_area.delete('1.0', tk.END)


class WebsiteStatus:
    def __init__(self, url):
        self.url = self.normalize_url(url)

    def normalize_url(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    def get_website_status(self):
        try:
            response = requests.get(self.url)
            return response.status_code
        except requests.RequestException as e:
            print(f"Error: {e}")
            return None

    def get_http_status(self):
        try:
            response = requests.head(self.url)
            return response.status_code
        except requests.RequestException as e:
            print(f"Error: {e}")
            return None


class UrlInfoRetriever:
    def __init__(self):
        pass

    def get_ip_address(self, url):
        try:
            ip_address = socket.gethostbyname(url)
            return ip_address
        except socket.gaierror:
            return None

    def get_server_info(self, url):
        try:
            response = requests.head(self.normalize_url(url))
            server_info = response.headers.get('server', 'Server information not available')
            return server_info
        except requests.RequestException:
            return None

    def get_whois_info(self, url):
        try:
            whois_info = whois.whois(url)
            return whois_info
        except whois.parser.PywhoisError:
            return None

    def normalize_url(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url


class SubdomainRetriever:
    def __init__(self):
        pass

    def get_subdomains_crtsh(self, url):
        try:
            crt_sh_url = f"https://crt.sh/?q={url}&output=json"
            response = requests.get(crt_sh_url)
            if response.status_code == 200:
                json_data = response.json()
                subdomains = set()
                for entry in json_data:
                    subdomains.add(entry['name_value'].strip())
                return list(subdomains)
            return []
        except requests.RequestException as e:
            print(f"Error: {e}")
            return None

    def get_subdomains_socket(self, url):
        try:
            cname_record = socket.gethostbyname(url)
            subdomains = [cname_record] if cname_record != url else []
            return subdomains
        except socket.gaierror:
            print(f"Domain not found: {url}")
        except Exception as e:
            print(f"Error: {e}")
        return None

    def get_all_subdomains(self, url):
        subdomains_crtsh = self.get_subdomains_crtsh(url) or []
        subdomains_socket = self.get_subdomains_socket(url) or []
        return list(set(subdomains_crtsh + subdomains_socket))


class WebPageInfo:
    def __init__(self, url):
        self.url = self.normalize_url(url)

    def normalize_url(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    def get_content_type(self):
        try:
            response = requests.head(self.url)
            content_type = response.headers.get('Content-Type')
            return content_type
        except requests.RequestException as e:
            print(f"Error: {e}")
            return None

    def get_metadata_type(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.content, 'html.parser')
            meta_tags = soup.find_all('meta')
            metadata_types = [meta.get('name') or meta.get('property') for meta in meta_tags]
            return metadata_types
        except requests.RequestException as e:
            print(f"Error: {e}")
            return None


# Unit Tests
class TestWebsiteStatus(unittest.TestCase):
    def setUp(self):
        self.url = "http://example.com"
        self.website_status = WebsiteStatus(self.url)

    @patch('requests.get')
    def test_get_website_status_success(self, mock_get):
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        result = self.website_status.get_website_status()
        self.assertEqual(result, 200)

    @patch('requests.get', side_effect=requests.RequestException('Mocked error'))
    def test_get_website_status_exception(self, mock_get):
        result = self.website_status.get_website_status()
        self.assertIsNone(result)

    @patch('requests.head')
    def test_get_http_status_success(self, mock_head):
        mock_response = mock_head.return_value
        mock_response.status_code = 302
        result = self.website_status.get_http_status()
        self.assertEqual(result, 302)

    @patch('requests.head', side_effect=requests.RequestException('Mocked error'))
    def test_get_http_status_exception(self, mock_head):
        result = self.website_status.get_http_status()
        self.assertIsNone(result)

    @patch('requests.head')
    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_get_ssl_certificate_info_success(self, mock_create_connection, mock_context, mock_head):
        mock_response = mock_head.return_value
        mock_response.headers = {}
        mock_socket = mock_create_connection.return_value.__enter__.return_value
        mock_ssl_socket = mock_context.return_value.wrap_socket.return_value
        mock_ssl_socket.getpeercert.return_value = {'subject': ((('commonName', 'example.com'),),)}
        result = self.website_status.get_ssl_certificate_info()
        self.assertIsNotNone(result)

    @patch('requests.get')
    def test_get_all_links_success(self, mock_get):
        mock_response = mock_get.return_value
        mock_response.content = '<a href="http://example.com/page1">Page 1</a>'
        result = self.website_status.get_all_links()
        self.assertEqual(result, ['http://example.com/page1'])

    def test_get_last_modification_date_success(self):
        with patch('requests.head') as mock_head:
            mock_response = mock_head.return_value
            mock_response.headers = {'last-modified': 'Thu, 01 Jan 1970 00:00:00 GMT'}
            result = self.website_status.get_last_modification_date()
            self.assertEqual(result, 'Thu, 01 Jan 1970 00:00:00 GMT')

    def test_get_last_modification_date_exception(self):
        with patch('requests.head', side_effect=requests.RequestException('Mocked error')) as mock_head:
            result = self.website_status.get_last_modification_date()
            self.assertIsNone(result)


# Entry point of the application
if __name__ == "__main__":
    root = tk.Tk()
    web_info_gui = WebInfoGUI(root)
    root.mainloop()
