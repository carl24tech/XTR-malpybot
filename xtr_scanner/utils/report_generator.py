
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from xml.etree import ElementTree as ET

from ..models.scan_result import ScanResult

class ReportGenerator:
    """Generate scan reports in various formats"""
    
    def generate_report(self, results: List[ScanResult], output_file: str,
                       format: str = "text", scan_duration: float = 0):
        """
        Generate scan report
        
        Args:
            results: List of scan results
            output_file: Output file path
            format: Report format (text, json, html)
            scan_duration: Total scan duration
        """
        output_path = Path(output_file)
        
        if format == "json":
            self._generate_json_report(results, output_path, scan_duration)
        elif format == "html":
            self._generate_html_report(results, output_path, scan_duration)
        else:
            self._generate_text_report(results, output_path, scan_duration)
    
    def _generate_json_report(self, results: List[ScanResult], output_path: Path, duration: float):
        """Generate JSON format report"""
        report = {
            "scanner": "XTR Malware Scanner",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "scan_duration": duration,
            "summary": {
                "total_scanned": len(results),
                "threats_detected": len([r for r in results if r.threats]),
                "clean_files": len([r for r in results if not r.threats and not r.error]),
                "errors": len([r for r in results if r.error])
            },
            "results": []
        }
        
        for result in results:
            report["results"].append({
                "file": result.file_path,
                "hash": result.file_hash,
                "size": result.file_size,
                "is_whitelisted": result.is_whitelisted,
                "error": result.error,
                "threats": [
                    {
                        "name": t.name,
                        "level": t.level.value,
                        "type": t.threat_type,
                        "description": t.description
                    }
                    for t in result.threats
                ]
            })
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _generate_html_report(self, results: List[ScanResult], output_path: Path, duration: float):
        """Generate HTML format report"""
        threats = [r for r in results if r.threats]
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XTR Malware Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .threat {{ background: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }}
        .clean {{ background: #e8f5e9; padding: 10px; margin: 10px 0; border-left: 4px solid #4caf50; }}
        .error {{ background: #fff3e0; padding: 10px; margin: 10px 0; border-left: 4px solid #ff9800; }}
        .level-critical {{ color: #d32f2f; }}
        .level-high {{ color: #f44336; }}
        .level-medium {{ color: #ff9800; }}
        .level-low {{ color: #2196f3; }}
    </style>
</head>
<body>
    <h1>XTR Malware Scanner - Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Duration: {duration:.2f} seconds</p>
        <p>Total Files: {len(results)}</p>
        <p>Threats Detected: {len(threats)}</p>
        <p>Clean Files: {len([r for r in results if not r.threats and not r.error])}</p>
        <p>Errors: {len([r for r in results if r.error])}</p>
    </div>
    <h2>Detailed Results</h2>
"""
        
        for result in results:
            if result.threats:
                html += f'<div class="threat">\n'
                html += f'    <strong>⚠️ {result.file_path}</strong><br>\n'
                for threat in result.threats:
                    html += f'    <span class="level-{threat.level.value}">🔴 {threat.name} ({threat.level.value})</span><br>\n'
                    html += f'    <small>{threat.description}</small><br>\n'
                html += '</div>\n'
            elif result.error:
                html += f'<div class="error">\n'
                html += f'    <strong>❌ {result.file_path}</strong><br>\n'
                html += f'    Error: {result.error}\n'
                html += '</div>\n'
            else:
                html += f'<div class="clean">\n'
                html += f'    <strong>✅ {result.file_path}</strong> - Clean\n'
                html += '</div>\n'
        
        html += """
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html)
    
    def _generate_text_report(self, results: List[ScanResult], output_path: Path, duration: float):
        """Generate text format report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("XTR MALWARE SCANNER - SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.2f} seconds\n")
            f.write(f"Total Files Scanned: {len(results)}\n")
            
            threats = [r for r in results if r.threats]
            f.write(f"Threats Detected: {len(threats)}\n")
            f.write(f"Clean Files: {len([r for r in results if not r.threats and not r.error])}\n")
            f.write(f"Errors: {len([r for r in results if r.error])}\n\n")
            
            if threats:
                f.write("-" * 80 + "\n")
                f.write("THREATS DETECTED\n")
                f.write("-" * 80 + "\n\n")
                
                for result in threats:
                    f.write(f"File: {result.file_path}\n")
                    for threat in result.threats:
                        f.write(f"  - {threat.name} [{threat.level.value}] - {threat.threat_type}\n")
                    f.write("\n")
