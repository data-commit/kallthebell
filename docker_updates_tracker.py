import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from github import Github, PullRequest
import re

class DockerUpdatesTracker:
    def __init__(self, github_token: str, repo_name: str):
        self.g = Github(github_token)
        self.repo = self.g.get_repo(repo_name)
        self.updates = []
        self.base_dir = 'docs/docker-updates'

    def _ensure_docs_directory(self):
        """Ensure the docs directory exists"""
        os.makedirs(self.base_dir, exist_ok=True)

    def _parse_dependabot_info(self, pr: PullRequest) -> Optional[Dict]:
        """Extract information from Dependabot PR"""
        if pr.user.login == 'dependabot[bot]':
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
            cves = re.findall(r'CVE-\d{4}-\d+', pr.body)
            security_keywords = ['security', 'vulnerability', 'exploit', 'patch', 'security advisory']
            
            if cves or any(keyword in pr.body.lower() for keyword in security_keywords):
                security_info['is_security'] = True
                security_info['cves'] = cves
                
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

            if pr.user.login == 'dependabot[bot]':
                update_info = self._parse_dependabot_info(pr)
            
            if not update_info and ('docker' in pr.title.lower() or 
                any('dockerfile' in f.filename.lower() for f in pr.get_files())):
                update_info = self._parse_version_from_dockerfile(pr)

            if update_info:
                security_info = self._extract_security_info(pr)
                
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
            return f"## Docker Updates ({today})\n\nNo Docker image updates in this period.\n"

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

        report = []
        for date in sorted(updates_by_date.keys(), reverse=True):
            report.append(f"## Docker Updates ({date})\n")
            updates = updates_by_date[date]
            
            if updates['security']:
                report.append("### Security Updates 🔒")
                for update in updates['security']:
                    report.append(self._format_security_update(update))
                report.append("")

            if updates['dependabot']:
                report.append("### Dependabot Updates 🤖")
                for update in sorted(updates['dependabot'], key=lambda x: x['image']):
                    report.append(self._format_dependabot_update(update))
                report.append("")

            for update_type, updates_list in updates['manual'].items():
                if updates_list:
                    emoji = {'major': '🚀', 'minor': '📦', 'patch': '🔧', 'unknown': '📋'}[update_type]
                    report.append(f"### {update_type.title()} Updates {emoji}")
                    for update in sorted(updates_list, key=lambda x: x['image']):
                        report.append(self._format_manual_update(update))
                    report.append("")

        return "\n".join(report)

    def _format_security_update(self, update: Dict) -> str:
        """Format a security update entry"""
        entry = [f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) 🔒"]
        
        if update['cves']:
            entry.append(f"  - CVEs: {', '.join(update['cves'])}")
        if update['security_notes']:
            entry.append(f"  - Security notes: {update['security_notes']}")
        return "\n".join(entry)

    def _format_dependabot_update(self, update: Dict) -> str:
        """Format a Dependabot update entry"""
        return (f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) 🤖")

    def _format_manual_update(self, update: Dict) -> str:
        """Format a manual update entry"""
        emoji = {
            'major': '🚀',
            'minor': '📦',
            'patch': '🔧',
            'unknown': '📋'
        }[update.get('update_type', 'unknown')]
        
        return (f"- Updated `{update['image']}` from {update['from_version']} "
                f"to {update['to_version']} (#{update['pr_number']}) {emoji}")

    def save_report(self):
        """Save the generated report to file"""
        self._ensure_docs_directory()
        
        month_year = datetime.now().strftime('%Y-%m')
        monthly_file = f"{self.base_dir}/docker-updates-{month_year}.md"
        
        report = self.generate_report()
        
        # Read existing content if file exists
        existing_content = ""
        if os.path.exists(monthly_file):
            with open(monthly_file, 'r') as f:
                existing_content = f.read()
        
        # Extract dates from new report
        dates_in_report = set(re.findall(r'## Docker Updates \((\d{4}-\d{2}-\d{2})\)', report))
        
        # Filter out sections from existing content that have dates in the new report
        filtered_content = []
        current_section = []
        skip_current_section = False
        
        for line in existing_content.split('\n'):
            date_match = re.match(r'## Docker Updates \((\d{4}-\d{2}-\d{2})\)', line)
            
            if date_match:
                # Save previous section if it wasn't skipped
                if current_section and not skip_current_section:
                    filtered_content.extend(current_section)
                    filtered_content.append('')  # Add spacing between sections
                
                # Start new section
                current_section = [line]
                skip_current_section = date_match.group(1) in dates_in_report
            else:
                current_section.append(line)
        
        # Handle the last section
        if current_section and not skip_current_section:
            filtered_content.extend(current_section)
        
        # Combine filtered content with new report
        final_content = []
        if filtered_content:
            # Remove trailing empty lines from filtered content
            while filtered_content and not filtered_content[-1].strip():
                filtered_content.pop()
            final_content.extend(filtered_content)
            final_content.append('')  # Add single spacing between old and new content
            
        final_content.append(report)
        
        # Write the combined content
        with open(monthly_file, 'w') as f:
            f.write('\n'.join(final_content))
        
        return report

if __name__ == '__main__':
    github_token = os.getenv('GITHUB_TOKEN')
    github_repository = os.getenv('GITHUB_REPOSITORY')
    
    if not github_token or not github_repository:
        print("Error: Required environment variables GITHUB_TOKEN and GITHUB_REPOSITORY not found")
        sys.exit(1)
        
    tracker = DockerUpdatesTracker(
        github_token=github_token,
        repo_name=github_repository
    )
    
    tracker.collect_updates()
    tracker.save_report()
