import logging
from updateutils import get_update_tool_callback
from auth.pdcpauth import check_and_validate_credentials
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define the banner with magenta color and green for the version
banner = f'''
{Fore.MAGENTA}
             __________________
  ____  ____/_  __/ ____/ ____/
 / __ \/ __ \/ / / __/ / /
/ /_/ / /_/ / / / /___/ /___
\____/ .___/_/ /_____/\____/
    /_/                         {Fore.GREEN}ver 1.0.0{Style.RESET_ALL}
    
{Style.RESET_ALL}
'''

# Show the banner to the user
def show_banner():
    print(f"{banner}")
    print("\t\toptec.asfaad.com\n")

# Update nuclei binary/tool to the latest version
def nuclei_tool_update_callback():
    show_banner()
    get_update_tool_callback('nuclei', '1.0.0')()

# Authenticate with PDCP
def auth_with_pdcp():
    show_banner()
    check_and_validate_credentials('nuclei')

# Example usage
if __name__ == "__main__":
    auth_with_pdcp()
    nuclei_tool_update_callback()
