# Cloudflare-DDNS-System
A simple DDNS implementation based on Cloudflare DNS service.

# System Requirements
* Have **Python 3.8.1** or newer version installed in your system.
	* Lower version of Python is *not* tested.

# Instructions
* Make sure module "PyCryptodome" is installed on your system.
* Run the script with *CPython* interpreter.
	* Other interpreter implementation is *not* tested.

## First-run
* The program asks for the **Zone ID** of your domain.
* You may then enter your **DNS dedicated API Token**, or **global API key (NOT SAFE)**.
	* If you insist on using your global API key, your **E-mail** address will be collected.
	* If you don't know what is API token and API key, click [me](https://api.cloudflare.com/#getting-started-requests).
	* If you don't know how to apply for a API token, click [me](https://support.cloudflare.com/hc/en-us/articles/200167836-Managing-API-Tokens-and-Keys#12345680).
		* You may use "Edit zone DNS" template or manually configure, as long as the token has the permission to edit your DNS records.
* The program provides IPv6 option if IPv6 is available, which you may choose to enable.
* The program generates a config file, where you may enable encryption.
* When global API key is provided, the encryption is mandatory.

## Configured
* If the config file was encrypted, you need to provide the correct password once the program starts.

# Attention
* Please make sure your server is connected to the Internet while using this system.
* If bugs occur, please open an issue and I'm looking forward to a detailed feedback.
