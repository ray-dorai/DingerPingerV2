#!/usr/bin/env python3
"""
Secure Network Scanner
Requires: Python 3.7+
Permissions: Standard user (no root needed)
Environment vars:
    SCANNER_KEY: Secret key for signing results
    SCANNER_RATE: Max concurrent scans (default 100)
    SCANNER_RETRIES: Max retries per host (default 2)
"""

from typing import Optional, Dict, List
import asyncio
import ipaddress
import logging
import ssl
import json
import os
from datetime import datetime
from dataclasses import dataclass
import hmac
import hashlib
from functools import partial

@dataclass
class ScanResult:
    ip: str
    status: str
    latency: float
    ports: Dict[int, bool]
    timestamp: str
    hash: str
    retry_count: int = 0

class SecureScanner:
    def __init__(self):
        self.rate_limit = int(os.getenv('SCANNER_RATE', '100'))
        self.max_retries = int(os.getenv('SCANNER_RETRIES', '2'))
        self.secret_key = os.getenv('SCANNER_KEY', '').encode() or os.urandom(32)
        
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        self.logger = self._setup_logging()
        self.ssl_context = self._setup_ssl()

    @staticmethod
    def _setup_logging():
        logger = logging.getLogger('secure_scanner')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(handler)
        return logger

    @staticmethod
    def _setup_ssl():
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _validate_ip(self, ip: str) -> bool:
        """Check if IP is valid and not in restricted ranges"""
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or 
                       addr.is_reserved or 
                       addr.is_multicast or
                       addr.is_loopback)
        except ValueError:
            return False

    async def check_host(self, ip: str, ports: List[int], 
                        retry_count: int = 0) -> Optional[ScanResult]:
        """Check a single host with retries"""
        if not self._validate_ip(ip):
            self.logger.warning(f"Invalid or restricted IP: {ip}")
            return None

        async with self.semaphore:
            try:
                start = datetime.now()
                port_status = {}
                
                for port in ports:
                    try:
                        connect = partial(
                            asyncio.open_connection, 
                            ip, 
                            port,
                            ssl=self.ssl_context if port == 443 else None
                        )
                        reader, writer = await asyncio.wait_for(
                            connect(), 
                            timeout=2.0
                        )
                        writer.close()
                        await writer.wait_closed()
                        port_status[port] = True
                    except:
                        port_status[port] = False

                latency = (datetime.now() - start).total_seconds() * 1000
                timestamp = datetime.utcnow().isoformat()

                result = ScanResult(
                    ip=ip,
                    status='up' if any(port_status.values()) else 'down',
                    latency=latency,
                    ports=port_status,
                    timestamp=timestamp,
                    hash='',
                    retry_count=retry_count
                )
                
                result.hash = self._sign_result(result)
                return result
                
            except Exception as e:
                self.logger.error(f"Error scanning {ip}: {str(e)}")
                # Retry logic
                if retry_count < self.max_retries:
                    await asyncio.sleep(1 * (retry_count + 1))  # Exponential backoff
                    return await self.check_host(ip, ports, retry_count + 1)
                return None

    def _sign_result(self, result: ScanResult) -> str:
        """Sign the result to prevent tampering"""
        msg = f"{result.ip}{result.status}{result.timestamp}".encode()
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    async def scan_network(self, ip_list: List[str], ports: List[int]) -> List[ScanResult]:
        valid_ips = [ip for ip in ip_list if self._validate_ip(ip)]
        ip_groups = self._group_by_subnet(valid_ips)
        
        results = []
        for subnet in ip_groups:
            subnet_tasks = [self.check_host(ip, ports) for ip in subnet]
            subnet_results = await asyncio.gather(*subnet_tasks)
            results.extend([r for r in subnet_results if r])
            await asyncio.sleep(0.5)  # Prevent subnet flooding
            
        return results

    def _group_by_subnet(self, ips: List[str], subnet_size: int = 24) -> List[List[str]]:
        """Group IPs by subnet to prevent network flooding"""
        subnets = {}
        for ip in ips:
            network = str(ipaddress.ip_network(f"{ip}/{subnet_size}", strict=False))
            subnets.setdefault(network, []).append(ip)
        return list(subnets.values())

    def save_results(self, results: List[ScanResult], filename: str):
        """Save results with proper file permissions"""
        with open(filename, 'w') as f:
            json.dump([vars(r) for r in results], f, indent=2)
        os.chmod(filename, 0o600)  # Restrict to user only
            
    def verify_results(self, filename: str) -> bool:
        """Verify results haven't been tampered with"""
        with open(filename) as f:
            data = json.load(f)
            for result in data:
                result_obj = ScanResult(**result)
                if result_obj.hash != self._sign_result(result_obj):
                    return False
        return True

async def main():
    # Set up signal handlers
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())

    scanner = SecureScanner()
    common_ports = [80, 443, 22, 25]
    
    try:
        with open('iplist.txt') as f:
            ips = f.read().splitlines()
    except FileNotFoundError:
        scanner.logger.error("iplist.txt not found")
        return
    
    results = await scanner.scan_network(ips, common_ports)
    scanner.save_results(results, 'scan_results.json')
    
    if scanner.verify_results('scan_results.json'):
        scanner.logger.info("Scan complete - results verified")
    else:
        scanner.logger.error("Result verification failed!")

if __name__ == '__main__':
    import signal
    asyncio.run(main())
