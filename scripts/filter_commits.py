""" Todo: add documentation
    To Execute:
       python filter_commits.py --sources sources.txt --range v6.6.10..v6.6.11 --output-dir ./results"""

import subprocess
import argparse
import os

def get_commits_between_tags(tag_range: str) -> str:
    """
    Get the commits between the specified tags using git log, excluding merge commits.
    Returns the output of `git log`.
    """
    cmd = ['git', 'log', '--no-merges', '--name-only', '--pretty=format:%H %s', tag_range]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise Exception(f"Error getting commits: {result.stderr}")

    return result.stdout

def filter_commits_by_sources(commits: str, sources: set) -> tuple[list[str], list[str]]:
    """
    Filters the commits to only those touching files in the sources set.
    Logs the commits that touch files not in the sources list.
    Returns a tuple of (filtered_commits, non_matching_commits).
    """
    filtered_commits = []
    non_matching_commits = []

    commit_lines = commits.split('\n\n')

    for commit_block in commit_lines:
        lines = commit_block.strip().splitlines()
        if not lines:
            continue

        commit_header = lines[0]  # First line is the commit hash and message
        changed_files = lines[1:]  # Remaining lines are file paths

        matching_files = [f for f in changed_files if f in sources]
        non_matching_files = [f for f in changed_files if f not in sources]

        if matching_files:
            filtered_commits.append(commit_header + '\n' + '\n'.join(matching_files))
        if non_matching_files:
            non_matching_commits.append(commit_header + '\n' + '\n'.join(non_matching_files))

    return filtered_commits, non_matching_commits

def write_to_file(filename: str, commits: list[str], title: str):
    """
    Writes the list of commits to a file with a header title.
    """
    with open(filename, 'w') as f:
        f.write(f"# {title}\n")
        f.write('\n\n'.join(commits))

def main():
    parser = argparse.ArgumentParser(description='Filter commits by source files.')
    parser.add_argument('-s', '--sources', required=True, help='Path to the sources.txt file.')
    parser.add_argument('-r', '--range', required=True, help='Kernel tag range (e.g., v6.6.10..v6.6.11).')
    parser.add_argument('-o', '--output-dir', default='.', help='Directory to write output files.')
    args = parser.parse_args()

    # Read source files from sources.txt
    with open(args.sources, 'r') as f:
        sources = set(line.strip() for line in f if line.strip())

    # Get the commits between the specified tags
    commits = get_commits_between_tags(args.range)

    # Filter the commits by source files
    filtered_commits, non_matching_commits = filter_commits_by_sources(commits, sources)

    # Write results to files
    os.makedirs(args.output_dir, exist_ok=True)
    filtered_output = os.path.join(args.output_dir, 'filtered_commits.txt')
    non_matching_output = os.path.join(args.output_dir, 'non_matching_commits.txt')

    write_to_file(filtered_output, filtered_commits, 'Filtered Commits (Matching Sources)')
    write_to_file(non_matching_output, non_matching_commits, 'Non-Matching Commits (Ignored)')

    print(f'Filtered commits written to {filtered_output}')
    print(f'Non-matching commits written to {non_matching_output}')

if __name__ == '__main__':
    main()
