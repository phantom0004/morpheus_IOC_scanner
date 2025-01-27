"""
Morpheus ASCII Art Banners
Author: Phantom0004 (Daryl Gatt)

Description:
This script provides customizable ASCII art banners for various modules and components of the Morpheus malware analysis framework. 
Each function returns an ASCII banner tailored to its respective module, enhancing the visual aesthetics and user experience.

Features:
- Main Program Banner: Displays the primary Morpheus domain banner with a thematic design.
- Scanner Banner: ASCII art highlighting the scanning functionality.
- VirusTotal Banner: Dedicated banner for VirusTotal integration.
- Setup Script Banner: Unique banner for the setup process.
- Updater Banner: Customizable ASCII banner for the database updater, accepting dynamic text.

Usage:
- Call the appropriate banner function (e.g., `morpheus_banner()`) to retrieve the ASCII art as a string.
- Use the returned string for display within the respective module or script.
"""

####################################
# ASCII Art for morpheus_scanner.py
####################################

def morpheus_banner():
    banner = r"""
         Into the Morpheous Domain
            Embrace the Unknown
                     
   .:'                                  `:.                                    
  ::'                                    `::                                   
 :: :.                                 .: ::                                  
  `:. `:.             .             .:'  .:'                                   
   `::. `::           !           ::' .::'                                     
       `::.`::.    .' ! `.    .::'.::'                                         
         `:.  `::::'':!:``::::'   ::'                                          
         :'*:::.  .:' ! `:.  .:::*`:                                           
        :: HHH::.   ` ! '   .::HHH ::                                          
       ::: `H TH::.  `!'  .::HT H' :::                                         
       ::..  `THHH:`:   :':HHHT'  ..::                                         
       `::      `T: `. .' :T'      ::'                                         
         `:. .   :         :   . .:'                                           
           `::'               `::'                                             
             :'  .`.  .  .'.  `:                                               
             :' ::.       .:: `:                                               
             :' `:::     :::' `:                                               
              `.  ``     ''  .'                                                
               :`...........':                                                 
               ` :`.     .': '                                                 
                `:  `---'  :'
    
               - Morpheus V2 -
    """
    
    return banner

def scan_banner():
    banner = r"""
       (  )   /\   _                 (     
    \ |  (  \ ( \.(               )                      _____
  \  \ \  `  `   ) \             (  ___                 / _   \
 (_`    \+   . x  ( .\            \/   \____-----------/ (o)   \_
- .-               \+  ;          (  O                           \____
Feel the blaze of Morpheus        \_____________  `              \  /
(__                +- .( -'.- <. - _  VVVVVVV VV V\                 \/
(_____            ._._: <_ - <- _  (--  _AAAAAAA__A_/                  |
  .    /./.+-  . .- /  +--  - .     \______________//_              \_______
  (__ ' /x  / x _/ (                                  \___'          \     /
 , x / ( '  . / .  /                                      |           \   /
    /  /  _/ /    +                                      /              \/
   '  (__/                                             /                  \
    
    """
    
    return banner

def virustotal_banner():
    banner = r"""
 _    ___                ______      __        __   ___    ____  ____
| |  / (_)______  ______/_  __/___  / /_____ _/ /  /   |  / __ \/  _/
| | / / / ___/ / / / ___// / / __ \/ __/ __ `/ /  / /| | / /_/ // /  
| |/ / / /  / /_/ (__  )/ / / /_/ / /_/ /_/ / /  / ___ |/ ____// /   
|___/_/_/   \__,_/____//_/  \____/\__/\__,_/_/  /_/  |_/_/   /___/  
 
                       Powered by Morpheus V2 
    """
    
    return banner
  
####################################
# ASCII Art for setup.py
####################################

def setup_script_banner():
  banner = """
\t\t\t⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣶⡞⡀⣤⣬⣴⠀⠀⢳⣶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀
\t\t\t⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⡇⠀⢸⣿⠿⣿⡇⠀⠀⠸⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀
\t\t\t⠀⠀⢠⡾⣫⣿⣻⣿⣽⣿⡇⠀⠈⢿⣧⡝⠟⠀⠀⢸⣿⣿⣿⣿⣿⣟⢷⣄⠀⠀
\t\t\t⠀⢠⣯⡾⢿⣿⣿⡿⣿⣿⣿⣆⣠⣶⣿⣿⣷⣄⣰⣿⣿⣿⣿⣿⣿⣿⢷⣽⣄⠀
\t\t\t⢠⣿⢋⠴⠋⣽⠋⡸⢱⣯⡿⣿⠏⣡⣿⣽⡏⠹⣿⣿⣿⡎⢣⠙⢿⡙⠳⡙⢿⠄
\t\t\t⣰⢣⣃⠀⠊⠀⠀⠁⠘⠏⠁⠁⠸⣶⣿⡿⢿⡄⠈⠀⠁⠃⠈⠂⠀⠑⠠⣈⡈⣧
\t\t\t⡏⡘⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡥⢄⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⢸
\t\t\t⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣄⣸⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢨
\t\t\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈
\t\t\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡳⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
    
  return banner

def setup_intro_banner():
  banner = r"""
    __  ___                 __                         _____      __            
   /  |/  /___  _________  / /_  ___  __  _______     / ___/___  / /___  ______ 
  / /|_/ / __ \/ ___/ __ \/ __ \/ _ \/ / / / ___/     \__ \/ _ \/ __/ / / / __ \
 / /  / / /_/ / /  / /_/ / / / /  __/ /_/ (__  )     ___/ /  __/ /_/ /_/ / /_/ /
/_/  /_/\____/_/  / .___/_/ /_/\___/\__,_/____/     /____/\___/\__/\__,_/ .___/ 
                 /_/                                                   /_/      
  """
  
  return banner

####################################
# ASCII Art for database_updater.py
####################################

def updater_banner(text):
  banner = rf"""
        ,     \    /      ,        
       / \    )\__/(     / \       
      /   \  (_\  /_)   /   \      
 ____/_____\__\@  @/___/_____\____ 
|             |\../|              |
|              \VV/               |
|         {text}        |
|_________________________________|
 |    /\ /      \\       \ /\    | 
 |  /   V        ))       V   \  | 
 |/     `       //        '     \| 
 `              V                '
  """
  
  return banner