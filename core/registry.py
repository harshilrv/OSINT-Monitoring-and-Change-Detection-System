from typing import List
from core.base_module import BaseModule

# Existing modules
from modules.subdomains.advanced_enum import AdvancedSubdomainEnum
from modules.subdomains.subfinder_enum import SubfinderEnum
from modules.subdomains.amass_enum import AmassEnum

# Phone OSINT module
from modules.PhoneOSINTModule.module import PhoneOSINTModule

# ✅ ADD THIS (username module)
from modules.username_osint.module import UsernameOSINTModule

# email OSINT module
from modules.emailosint.module import EmailOSINTModule
def get_modules_for_target(target_type: str) -> List[BaseModule]:

    modules: List[BaseModule] = [
        # Subdomain modules
        AdvancedSubdomainEnum(),
        SubfinderEnum(),
        AmassEnum(),

        # Phone OSINT
        PhoneOSINTModule(),

        # ✅ Username OSINT (NEW)
        UsernameOSINTModule(),
        EmailOSINTModule(),
    ]

    return [
        module for module in modules
        if target_type in module.supported_targets
    ]