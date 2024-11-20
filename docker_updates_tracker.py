import os
import sys
from datetime import datetime, timedelta, timezone
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

    def _get_commit_type(self, commit_message: str) -> Optional[str]:
        """Extract update type from commit message"""
        if '#major:' in commit_message.lower():
            return 'major'
        elif '#minor:' in commit_message.lower():
            return 'minor'
        elif '#patch:' in commit_message.lower():
            return 'patch'
        return None

    def _determine_update_type(self, pr: PullRequest) -> str:
        """Determine update type from commit messages"""
        # First check commit messages
        commits = pr.get_commits()
        for commit in commits:
            commit_type = self._get_commit_type(commit.commit.message)
            if commit_type:
                return commit_type

        # If no commit has type, try to determine from version changes
        return self._determine_update_type_from_version_change(pr.title)

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

    def _parse_version_from_dockerfile(self, pr: PullRequest) -> Optional[Dict]:
        """Extract version changes from Dockerfile changes"""
        for file in pr.get_files():
            if 'dockerfile' in file.filename.lower():
                patch = file.patch
                if patch:
                    # Look for FROM statements changes
                    from_changes = re.findall(r'-FROM\s+(\w+):([\d\.]+).*?\n\+FROM\s+(\w+):([\d\.]+)', patch, re.IGNORECASE)
                    if from_changes:
                        old_image, old_ver, new_image, new_ver = from_changes[0]
                        return {
                            'image': new_image,
                            'from_version': old_ver,
                            'to_version': new_ver,
                            'update_type': self._determine_update_type(pr),
                            'is_dependabot': False
                        }
        return None

    def _extract_security_info(self, pr: PullRequest) -> Dict:
        """Extract security-related information from PR"""
        security_info = {
            'is_security': False,
            'cves': [],
            'security_notes': ''
        }

        content_to_check = f"{pr.title} {pr.body or ''}"
        for commit in pr.get_commits():
            content_to_check += f" {commit.commit.message}"

        cves = re.findall(r'CVE-\d{4}-\d+', content_to_check)
        security_keywords = ['security', 'vulnerability', 'exploit', 'patch', 'security advisory']
        
        if cves or any(keyword in content_to_check.lower() for keyword in security_keywords):
            security_info['is_security'] = True
            security_info['cves'] = list(set(cves))  # Remove duplicates
            
            security_notes = []
            for line in content_to_check.split('\n'):
                if any(keyword in line.lower() for keyword in security_keywords):
                    security_notes.append(line.strip())
            security_info['security_notes'] = '\n'.join(security_notes)

        return security_info

    def collect_updates(self, days_back: int = 14):
        """Collect Docker image updates from recent PRs"""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        pulls = self.repo.get_pulls(state='closed', sort='updated', direction='desc')

        for pr in pulls:
            if not pr.merged or pr.merged_at < since_date:
                continue

            has_dockerfile_changes = any(
                'dockerfile' in f.filename.lower() 
                for f in pr.get_files()
            )

            if not has_dockerfile_changes:
                continue

            update_info = self._parse_dependabot_info(pr) if pr.user.login == 'dependabot[bot]' else None
            
            if not update_info:
                update_info = self._parse_version_from_dockerfile(pr)

            if update_info:
                security_info = self._extract_security_info(pr)
                
                # Collect all commit messages
                commit_messages = [
                    f"- {commit.commit.message.strip()}"
                    for commit in pr.get_commits()
                ]

                update_info.update({
                    'pr_number': pr.number,
                    'pr_title': pr.title,
                    'merged_at': pr.merged_at,
                    'merged_by': pr.merged_by.login if pr.merged_by else 'unknown',
                    **security_info,
                    'description': (
                        f"{pr.body[:500] if pr.body else ''}\n\n"
                        f"Commit messages:\n{chr(10).join(commit_messages)}"
                    )
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
        
        # Handle existing content
        existing_content = ""
        if os.path.exists(monthly_file):
            with open(monthly_file, 'r') as f:
                existing_content = f.read()
        
        dates_in_report = set(re.findall(r'## Docker Updates \((\d{4}-\d{2}-\d{2})\)', report))
        
        filtered_content = []
        current_section = []
        skip_current_section = False
        
        for line in existing_content.split('\n'):
            date_match = re.match(r'## Docker Updates \((\d{4}-\d{2}-\d{2})\)', line)
            
            if date_match:
                if current_section and not skip_current_section:
                    filtered_content.extend(current_section)
                    filtered_content.append('')
                
                current_section = [line]
                skip_current_section = date_match.group(1) in dates_in_report
            else:
                current_section.append(line)
        
        if current_section and not skip_current_section:
            filtered_content.extend(current_section)
        
        final_content = []
        if filtered_content:
            while filtered_content and not filtered_content[-1].strip():
                filtered_content.pop()
            final_content.extend(filtered_content)
            final_content.append('')
            
        final_content.append(report)
        
        with open(monthly_file, 'w') as f:
            f.write('\n'.join(final_content))

if __name__ == '__main__':
    github_token = os.getenv('GITHUB_TOKEN')
    github_repository = os.getenv('GITHUB_REPOSITORY')
    
    if not github_token or not github_repository:
        print("Error: Required environment variables GITHUB_
