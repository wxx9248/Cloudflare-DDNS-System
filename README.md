# Cloudflare-DDNS-System
A simple DDNS implementation based on Cloudflare DNS service.

# System Requirements
* The program is designed for **Windows** currently.
* Have **Python 3.7.6** or newer version installed in your system.

# Instructions
* Make
* Make sure module "PyCryptodome" is installed on your system
* Run the script with a win32 interpreter

## First-run
* The program asks for your **E-mail** address and the **Zone ID** of your domain
* You may then enter your **DNS dedicated API Token**, or **global API key (NOT SAFE)**
* The program provides IPv6 option if IPv6 is available, which you may choose to enable.
* The program generates a config file, where you may enable encryption.
 * When global API key is provided, the encryption is mandatory.

## Configured
* If the config file was encrypted, you need to provide the correct password once the program starts.

# Attention
* Please make sure your server is continuously connected to the Internet while using this system.
* If bugs occur, please open an issue and I'm looking forward to a detailed feedback.
