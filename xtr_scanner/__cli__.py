#!/usr/bin/env python3
"""
XTR Malware Scanner - Command Line Interface
Brand: XTR Softwares
"""

import argparse
import sys
import os
from pathlib import Path
from colorama import init, Fore, Style
from datetime import datetime
from typing import List, Optional

from .scanner.engine import ScanEngine
from .utils.logger import setup_logger
from .utils.report_generator import ReportGenerator
from .models.threat import ThreatLevel

init(autoreset=True)

logger = setup_logger("cli")

class XTRBanner:
    """ASCII Art Banner for XTR Softwares"""
    
    BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                                   ║
{Fore.CYAN}║  {Fore.YELLOW}██████╗ {Fore.RED}████████╗{Fore.GREEN}██████╗ {Fore.CYAN}    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}██╔══██╗{Fore.RED}╚══██╔══╝{Fore.GREEN}██╔══██╗{Fore.CYAN}    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗{Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}██████╔╝{Fore.RED}   ██║   {Fore.GREEN}██████╔╝{Fore.CYAN}    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝{Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}██╔══██╗{Fore.RED}   ██║   {Fore.GREEN}██╔══██╗{Fore.CYAN}    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗{Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}██║  ██║{Fore.RED}   ██║   {Fore.GREEN}██║  ██║{Fore.CYAN}    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║{Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}╚═╝  ╚═╝{Fore.RED}   ╚═╝   {Fore.GREEN}╚═╝  ╚═╝{Fore.CYAN}    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Fore.CYAN}║
{Fore.CYAN}║                                                                   ║
{Fore.CYAN}║{Fore.WHITE}                    PROFESSIONAL MALWARE SCANNER                   {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}                         {Fore.MAGENTA}v1.0.0{Fore.WHITE} | XTR Softwares                       {Fore.CYAN}║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class XTRCLI:
    """Command Line Interface for XTR Malware Scanner"""
    
    def __init__(self):
        self.scan_engine = ScanEngine()
        self.report_gen = ReportGenerator()
        
    def run(self):
        """Main CLI entry point"""
        parser = self._create_parser()
        args = parser.parse_args()
        
        if not hasattr(args, 'func'):
            parser.print_help()
            return
            
        try:
            args.func(args)
        except KeyboardInterrupt:
            self._print_warning("\n[!] Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            self._print_error(f"An error occurred: {str(e)}")
            sys.exit(1)
    
    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog="xtr-scan",
            description="XTR Malware Scanner - Advanced Malware Detection Tool",
            epilog="For more information visit: https://xtrsoftwares.com"
        )
        
        parser.add_argument(
            "-v", "--version",
            action="version",
            version="XTR Malware Scanner v1.0.0 (XTR Softwares)"
        )
        
        subparsers = parser.add_subparsers()
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Scan files or directories")
        scan_parser.add_argument(
            "target",
            help="File or directory to scan"
        )
        scan_parser.add_argument(
            "-r", "--recursive",
            action="store_true",
            help="Scan directories recursively"
        )
        scan_parser.add_argument(
            "-o", "--output",
            help="Save scan report to file"
        )
        scan_parser.add_argument(
            "-f", "--format",
            choices=["text", "json", "html"],
            default="text",
            help="Report format (default: text)"
        )
        scan_parser.add_argument(
            "--heuristic",
            action="store_true",
            help="Enable heuristic analysis"
        )
        scan_parser.add_argument(
            "--yara",
            help="Use custom YARA rules file"
        )
        scan_parser.add_argument(
            "--no-color",
            action="store_true",
            help="Disable colored output"
        )
        scan_parser.set_defaults(func=self._scan_command)
        
        # Update signatures command
        update_parser = subparsers.add_parser("update", help="Update malware signatures")
        update_parser.set_defaults(func=self._update_command)
        
        # Real-time monitor command
        monitor_parser = subparsers.add_parser("monitor", help="Real-time file system monitoring")
        monitor_parser.add_argument(
            "path",
            help="Directory to monitor"
        )
        monitor_parser.set_defaults(func=self._monitor_command)
        
        # Database commands
        db_parser = subparsers.add_parser("database", help="Database operations")
        db_subparsers = db_parser.add_subparsers()
        
        update_db = db_subparsers.add_parser("update", help="Update signature database")
        update_db.set_defaults(func=self._update_db_command)
        
        return parser
    
    def _scan_command(self, args):
        """Handle scan command"""
        if args.no_color:
            global Fore, Style
            Fore = Style = type('Dummy', (), {'RESET_ALL': '', 'RED': '', 'GREEN': '', 
                                              'YELLOW': '', 'BLUE': '', 'MAGENTA': '', 'CYAN': ''})()
        
        self._print_banner()
        self._print_info(f"Target: {args.target}")
        self._print_info(f"Recursive: {args.recursive}")
        self._print_info(f"Heuristic: {args.heuristic}")
        
        target_path = Path(args.target)
        
        if not target_path.exists():
            self._print_error(f"Target does not exist: {args.target}")
            return
        
        # Start scan
        start_time = datetime.now()
        
        if target_path.is_file():
            result = self.scan_engine.scan_file(target_path, heuristic=args.heuristic)
            results = [result]
        else:
            results = self.scan_engine.scan_directory(
                target_path,
                recursive=args.recursive,
                heuristic=args.heuristic
            )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Display results
        self._display_results(results, duration)
        
        # Generate report
        if args.output:
            self.report_gen.generate_report(
                results,
                output_file=args.output,
                format=args.format,
                scan_duration=duration
            )
            self._print_success(f"Report saved to: {args.output}")
    
    def _update_command(self, args):
        """Handle update command"""
        self._print_banner()
        self._print_info("Updating malware signatures...")
        
        try:
            self.scan_engine.update_signatures()
            self._print_success("Signatures updated successfully!")
        except Exception as e:
            self._print_error(f"Failed to update signatures: {str(e)}")
    
    def _monitor_command(self, args):
        """Handle real-time monitoring"""
        self._print_banner()
        self._print_info(f"Monitoring directory: {args.path}")
        self._print_info("Press Ctrl+C to stop monitoring\n")
        
        try:
            self.scan_engine.realtime_monitor(args.path)
        except KeyboardInterrupt:
            self._print_warning("\nMonitoring stopped")
    
    def _update_db_command(self, args):
        """Handle database update"""
        self._print_banner()
        self._print_info("Updating signature database...")
        
        try:
            from .database.signature_db import SignatureDatabase
            db = SignatureDatabase()
            db.update_from_online()
            self._print_success("Database updated successfully!")
        except Exception as e:
            self._print_error(f"Failed to update database: {str(e)}")
    
    def _display_results(self, results, duration):
        """Display scan results in a formatted table"""
        from prettytable import PrettyTable
        
        threats = [r for r in results if r.threats]
        clean = [r for r in results if not r.threats]
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Total files scanned: {len(results)}")
        print(f"Threats detected: {len(threats)}")
        print(f"Clean files: {len(clean)}")
        print(f"Scan duration: {duration:.2f} seconds")
        
        if threats:
            print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.RED}THREATS DETECTED{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
            
            table = PrettyTable()
            table.field_names = ["File", "Threat", "Level", "Type"]
            table.align = "l"
            
            for result in threats:
                for threat in result.threats:
                    level_color = {
                        ThreatLevel.CRITICAL: Fore.RED,
                        ThreatLevel.HIGH: Fore.LIGHTRED_EX,
                        ThreatLevel.MEDIUM: Fore.YELLOW,
                        ThreatLevel.LOW: Fore.BLUE
                    }.get(threat.level, Fore.WHITE)
                    
                    table.add_row([
                        result.file_path,
                        threat.name,
                        f"{level_color}{threat.level.value}{Style.RESET_ALL}",
                        threat.threat_type
                    ])
            
            print(table)
    
    def _print_banner(self):
        """Print XTR banner"""
        print(XTRBanner.BANNER)
    
    def _print_info(self, message):
        """Print info message"""
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def _print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def _print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")
    
    def _print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} {message}")

def main():
    """Main entry point for CLI"""
    cli = XTRCLI()
    cli.run()

if __name__ == "__main__":
    main()
