import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from github import Github, PullRequest
import re

class DockerUpdatesTracker:
    def __init__(self, github_token: str, repo_name: str, output_file: str = 'docker_updates.md'):
        self.g = Github(github_token)
        self.repo = self.g.get_repo(repo_name)
        self.updates = []
        self.output_file = output_file
        self.base_dir = 'docs/docker-updates'

    def _ensure_docs_directory(self):
        """Ensure the docs directory exists and has initial structure"""
        os.makedirs(self.base_dir, exist_ok=True)
        readme_path = f"{self.base_dir}/README.md"
        if not os.path.exists(readme_path):
            with open(readme_path, 'w') as f:
                f.write("""# Docker Image Updates Log

This directory tracks all Docker image updates across our infrastructure, including:
- Version updates (major, minor, patch)
- Security patches and vulnerability fixes
- Dependabot automated updates
- Manual updates

## Directory Structure
- Monthly files (YYYY-MM.md) contain detailed update logs
- Each update includes PR reference, update type, and relevant details
- Security updates are prominently marked
- Dependabot updates are tracked separately

## Update Types
🔒 Security Updates: Critical security patches and CVE fixes
🚀 Major Updates: Breaking changes and major version bumps
📦 Minor Updates: New features without breaking changes
🔧 Patch Updates: Bug fixes and patch releases
🤖 Dependabot: Automated dependency updates
""")

    def _parse_dependabot_info(self, pr: PullRequest) -> Optional[Dict]:
        """Extract information from Dependabot PR"""
        if pr.user.login == 'dependabot[bot]':
            # Parse Dependabot PR title pattern: "Bump image from X.X.X to Y.Y.Y"
            pattern = r'bump (\w+) from ([\d\.]+) to ([\d\.]+)'
            match = re.search(pattern, pr.title.lower())
            if match:
                image, old_ver, new_ver = match.groups()
                return {
                    'image': image,
                    'from_version': old_ver,
                    'to_version': new_ver,
                    'is_dependabot': True
                }
        return None

    def _parse_version_from_dockerfile(self, pr: PullRequest) -> Optional[Dict]:
        """Extract version changes from Dockerfile changes"""
        for file in pr.get_files():
            if 'dockerfile' in file.filename.lower():
                patch = file.patch
                if patch:
                    # Look for FROM statements changes
                    from_changes = re.findall(r'-FROM \w+:([\d\.]+).*\n\+FROM \w+:([\d\.]+)', patch)
                    if from_changes:
                        old_ver, new_ver = from_changes[0]
                        image_name = re.search(r'FROM (\w+):', patch.split('\n')[1])
                        if image_name:
                            return {
                                'image': image_name.group(1),
                                'from_version': old_ver,
                                'to_version': new_ver,
                                'update_type': self._determine_update_type(pr.title),
                                'is_dependabot': False
                            }
        return None

    def _determine_update_type(self, title: str) -> str:
        """Determine update type from commit message"""
        if '#major:' in title.lower():
            return 'major'
        elif '#minor:' in title.lower():
            return 'minor'
        elif '#patch:' in title.lower():
            return 'patch'
        # Try to determine from version change if no explicit tag
        return self._determine_update_type_from_version_change(title)

    def _determine_update_type_from_version_change(self, title: str) -> str:
        """Try to determine update type from version numbers"""
        version_pattern = r'([\d\.]+) to ([\d\.]+)'
        match = re.search(version_pattern, title)
        if match:
            old_ver = match.group(1).split('.')
            new_ver = match.group(2).split('.')
            
            if len(old_ver) >= 1 and len(new_ver) >= 1:
                if old_ver[0] != new_ver[0]:
                    return 'major'
                elif len(old_ver) >= 2 and len(new_ver) >= 2 and old_ver[1] != new_ver[1]:
                    return 'minor'
                else:
                    return 'patch'
        return 'unknown'

    def _extract_security_info(self, pr: PullRequest) -> Dict:
        """Extract security-related information from PR"""
        security_info = {
            'is_security': False,
            'cves': [],
            'security_notes': ''
        }

        if pr.body:
            # Look for CVE mentions
            cves = re.findall(r'CVE-\d{4}-\d+', pr.body)
            security_keywords = ['security', 'vulnerability', 'exploit', 'patch', 'security advisory']
            
            if cves or any(keyword in pr.body.lower() for keyword in security_keywords):
                security_info['is_security'] = True
                security_info['cves'] = cves
                
                # Extract security-related notes
                body_lines = pr.body.split('\n')
                security_notes = []
                for line in body_lines:
                    if any(keyword in line.lower() for keyword in security_keywords):
                        security_notes.append(line.strip())
                security_info['security_notes'] = '\n'.join(security_notes)

        return security_info

    def collect_updates(self, days_back: int = 14):
        """Collect Docker image updates from recent PRs"""
        since_date = datetime.now() - timedelta(days=days_back)
        pulls = self.repo.get_pulls(state='closed', sort='updated', direction='desc')

        for pr in pulls:
            if not pr.merged or pr.merged_at < since_date:
                continue

            update_info = None

            # Check for Dependabot updates first
            if pr.user.login == 'dependabot[bot]':
                update_info = self._parse_dependabot_info(pr)
            
            # If not Dependabot or parsing failed, check for manual updates
            if not update_info and ('docker' in pr.title.lower() or 
                any('dockerfile' in f.filename.lower() for f in pr.get_files())):
                update_info = self._parse_version_from_dockerfile(pr)

            if update_info:
                # Get security information
                security_info = self._extract_security_info(pr)
                
                # Combine all information
                update_info.update({
                    'pr_number': pr.number,
                    'pr_title': pr.title,
                    'merged_at': pr.merged_at,
                    'merged_by': pr.merged_by.login if pr.merged_by else 'unknown',
                    **security_info,
                    'description': pr.body[:500] if pr.body else ''
                })
                self.updates.append(update_info)

    def generate_report(self) -> str:
        """Generate a detailed report of Docker image updates"""
        if not self.updates:
            today = datetime.now().strftime('%Y-%m-%d')
            return f"\n## Docker Image Updates ({today})\n\nNo Docker image updates in this period.\n"

        # Group updates by date
        updates_by_date = {}
        for update in self.updates:
            date = update['merged_at'].strftime('%Y-%m-%d')
            if date not in updates_by_date:
                updates_by_date[date] = {
                    'security': [],
                    'dependabot': [],
                    'manual': {'major': [], 'minor': [], 'patch': [], 'unknown': []}
                }
            
            if update['is_security']:
                updates_by_date[date]['security'].append(update)
            elif update.get('is_dependabot'):
                updates_by_date[date]['dependabot'].append(update)
            else:
                update_type = update.get('update_type', 'unknown')
                updates_by_date[date]['manual'][update_type].append(update)

        report = ""
        for date in sorted(updates_by_date.keys(), reverse=True):
            report += f"\n## Docker Image Updates ({date})\n\n"
            updates = updates_by_date[date]
            
            # Security updates first
            if updates['security']:
                report += "### Security Updates 🔒\n"
                for update in updates['security']:
                    report += self._format_security_update(update)
                report += "\n"

            # Dependabot updates
            if updates['dependabot']:
                report += "### Dependabot Updates 🤖\n"
                for update in sorted(updates['dependabot'], key=lambda x: x['image']):
                    report += self._format_dependabot_update(update)
                report += "\n"

            # Manual updates by type
            for update_type, updates_list in updates['manual'].items():
                if updates_list:
                    emoji = {'major': '🚀', 'minor': '📦', 'patch': '🔧', 'unknown': '📋'}[update_type]
                    report += f"### {update_type.title()} Updates {emoji}\n"
                    for update in sorted(updates_list, key=lambda x: x['image']):
                        report += self._format_manual_update(update)
                    report += "\n"

        return report

    def _format_security_update(self, update: Dict) -> str:
        """Format a security update entry"""
        entry = (f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) 🔒\n")
        
        if update['cves']:
            entry += f"  - CVEs: {', '.join(update['cves'])}\n"
        if update['security_notes']:
            entry += f"  - Security notes: {update['security_notes']}\n"
        return entry

    def _format_dependabot_update(self, update: Dict) -> str:
        """Format a Dependabot update entry"""
        return (f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) 🤖\n")

    def _format_manual_update(self, update: Dict) -> str:
        """Format a manual update entry"""
        emoji = {
            'major': '🚀',
            'minor': '📦',
            'patch': '🔧',
            'unknown': '📋'
        }[update.get('update_type', 'unknown')]
        
        return (f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) {emoji}\n")

    def save_report(self):
        """Save the generated report to file"""
        self._ensure_docs_directory()
        
        month_year = datetime.now().strftime('%Y-%m')
        monthly_file = f"{self.base_dir}/{month_year}.md"
        
        report = self.generate_report()
        
        # Create or append to monthly file
        mode = 'a' if os.path.exists(monthly_file) else 'w'
        with open(monthly_file, mode) as f:
            f.write(report)
        
        return report

if __name__ == '__main__':
    tracker = DockerUpdatesTracker(
        github_token=os.getenv('GITHUB_TOKEN'),
        repo_name=os.getenv('GITHUB_REPOSITORY')
    )
    
    tracker.collect_updates()
    tracker.save_report()