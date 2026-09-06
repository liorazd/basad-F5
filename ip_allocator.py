import ipaddress
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

class VIPIPAllocator:
    """
    Manages VIP IP allocation across multiple /24 subnets per F5 environment.
    - Fetches existing VIPs from F5
    - Allocates next available IP from the environment's configured vip_networks
      (f5_environments.json), tried in order
    - Reserves .0 (network), .1 (gateway), .255 (broadcast)
    - Reserves .250-.254 ONLY when moving to next subnet (not in current use)
    """

    # Always reserved: .0 (network), .1 (gateway), .255 (broadcast)
    ALWAYS_RESERVED = {0, 1, 255}

    # Reserved when transitioning to NEXT subnet: .250-.254
    RESERVED_ON_TRANSITION = {250, 251, 252, 253, 254}

    def __init__(self, f5_client, environment: str, vip_networks: List[str]):
        """
        Initialize allocator with F5 client and the environment's VIP subnets.

        Args:
            f5_client: F5Client instance to query existing VIPs.
            environment: environment id, used for logging/error messages
            vip_networks: ordered list of CIDR ranges to allocate VIP IPs from
                          (the environment's vip_networks in f5_environments.json)
        """
        self.f5_client = f5_client
        self.environment = environment.lower()
        self.subnet_ranges = list(vip_networks or [])
        self.allocated_ips = set()

        if not self.subnet_ranges:
            raise RuntimeError(
                f"No vip_networks configured for environment '{self.environment}'. "
                f"Add a vip_networks array to this environment in f5_environments.json."
            )

        self._load_existing_vips()
    
    def _load_existing_vips(self):
        """
        Query the load balancer for existing VIP IPs so we never hand out a
        duplicate. Works for any client exposing `list_allocated_vip_ips()`;
        falls back to the F5 iControl call otherwise.
        """
        lister = getattr(self.f5_client, "list_allocated_vip_ips", None)
        if callable(lister):
            try:
                self.f5_client.ensure_login()
                self.allocated_ips.update(lister())
                logger.info("Loaded %d existing VIPs (%s environment)", len(self.allocated_ips), self.environment)
            except Exception as e:
                logger.error("Error loading existing VIPs via client: %s", e)
            return
        try:
            self.f5_client.ensure_login()
            url = f"{self.f5_client.base_url}/mgmt/tm/ltm/virtual"
            
            resp = self.f5_client.session.get(url, verify=self.f5_client.verify_ssl)
            if resp.status_code != 200:
                logger.warning("Could not fetch existing VIPs from F5: %s", resp.status_code)
                return
            
            data = resp.json()
            items = data.get("items", [])
            
            for item in items:
                destination = item.get("destination", "")
                # destination format: "/partition/ip:port"
                if "/" in destination:
                    ip_part = destination.split("/")[-1].split(":")[0]
                    try:
                        ipaddress.IPv4Address(ip_part)
                        self.allocated_ips.add(ip_part)
                        logger.debug("Loaded existing VIP: %s", ip_part)
                    except ipaddress.AddressValueError:
                        pass
            
            logger.info("Loaded %d existing VIPs from F5 (%s environment)", len(self.allocated_ips), self.environment)
        
        except Exception as e:
            logger.error("Error loading existing VIPs: %s", e)
            # Don't fail; just continue with empty set
    
    def allocate_ip(self) -> str:
        """
        Allocate the next available VIP IP from the environment's configured ranges.

        Logic:
        1. Walk the environment's vip_networks in configured order
        2. For current subnet: Skip .0, .1, .255 (and allocated IPs)
        3. For .250-.254 in current subnet: Use them if available
        4. When current subnet is full: Move to next subnet
        5. For next subnet: Skip .0, .1, .250-.254, .255

        Raises RuntimeError if all subnets are exhausted.
        """
        subnet_ranges = self.subnet_ranges

        for subnet_idx, subnet_str in enumerate(subnet_ranges):
            try:
                subnet = ipaddress.IPv4Network(subnet_str, strict=False)
                logger.info("Checking subnet [%d] for %s: %s", subnet_idx, self.environment, subnet_str)
                
                # Determine if this is the last subnet
                is_last_subnet = (subnet_idx == len(subnet_ranges) - 1)
                
                # Get all usable hosts in the /24 (.1 through .254)
                for host in subnet.hosts():
                    ip_str = str(host)
                    suffix = host.packed[-1]  # Last octet
                    
                    # Always skip .0, .1, .255
                    if suffix in self.ALWAYS_RESERVED:
                        logger.debug("Skipping always-reserved IP: %s", ip_str)
                        continue
                    
                    # If this is NOT the last subnet, also skip .250-.254
                    # (reserve them for transitioning to next subnet)
                    if not is_last_subnet and suffix in self.RESERVED_ON_TRANSITION:
                        logger.debug("Skipping reserved-on-transition IP: %s", ip_str)
                        continue
                    
                    # Skip already allocated IPs
                    if ip_str in self.allocated_ips:
                        logger.debug("Skipping allocated IP: %s", ip_str)
                        continue
                    
                    # Found available IP!
                    self.allocated_ips.add(ip_str)
                    logger.info("Allocated VIP IP: %s from subnet %s (%s)", ip_str, subnet_str, self.environment)
                    return ip_str
                
                logger.warning("Subnet %s is full (or exhausted), trying next range", subnet_str)
            
            except ipaddress.AddressValueError as e:
                logger.error("Invalid subnet config: %s - %s", subnet_str, e)
                continue
        
        # All subnets exhausted
        raise RuntimeError(
            f"No available VIP IPs in any configured {self.environment} subnet. "
            f"Ranges: {', '.join(subnet_ranges)}"
        )
