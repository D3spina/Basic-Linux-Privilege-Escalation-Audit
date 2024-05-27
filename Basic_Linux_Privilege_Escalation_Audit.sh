#!/bin/bash
# Created by d3spina
#
# ---------------------------------------------------------------------
# Script Name: Linux Security Auditor
# Description: This script checks various security aspects of a Linux
# server including permissions, potential vulnerabilities, and key
# configurations. It provides a quick overview of the system's security
# posture.
# Usage:
# chmod +x Basic_Linux_Privilege_Escalation_Audit.sh
# ./Basic_Linux_Privilege_Escalation_Audit.sh
# OR
# ./Basic_Linux_Privilege_Escalation_Audit.sh > audit.txt
#
# # DISCLAIMER:
# This script is provided for educational purposes only. Use of this script
# for testing, either on your own systems or on systems for which you have
# legal authorization to perform such tests, is highly encouraged. However,
# executing this script on systems without such authorization is illegal and
# strictly forbidden. The creator of this script assumes no liability for
# misuse of this tool or any damage that might be caused by its appropriate
# or inappropriate use. It is the end user's responsibility to comply with
# all applicable local, state, and federal laws. Users must consider the
# impact of any actions they perform and be mindful of the applicable laws
# and rights of others.
#
# By running this script, you agree to the terms of use and acknowledge
# that you have the necessary authorizations to perform such assessments.
# ---------------------------------------------------------------------

check_commands() {
	for cmd in find sudo awk grep curl; do
		if ! command -v $cmd &>/dev/null; then
			echo "$cmd is required but not installed. Exiting."
			exit 1
		fi
	done
}

main() {
	echo "######################################"
	echo "Basic Linux Privilege Escalation Audit"
	echo "Audit Date: $(date)"
	echo "######################################"

	# Check for required commands before continuing
	check_commands

	echo "######################################"
	echo "Checking Write Permissions on Sensitive Password Files"
	actualPath=$(pwd)                                  # Stores the current directory path in a variable.
	files=("/etc/passwd" "/etc/shadow" "/etc/sudoers") # List of critical files to check.

	for file in "${files[@]}"; do
		if [ -w "$file" ]; then
			echo "/!\ You have write permission on $file"
		else
			echo "You don't have write permission on $file"
		fi
	done

	echo "#####################################"
	echo "Searching for authorized_keys files"

	keys=$(find / -name authorized_keys 2>/dev/null) # Search the entire file system for 'authorized_keys' files, suppressing error messages.
	if [ -n "$keys" ]; then
		echo "authorized_keys files found:"
		echo "$keys"
	else
		echo "No authorized_keys files found."
	fi

	echo "Searching for RSA key files"

	rsa_keys=$(find / -name id_rsa 2>/dev/null) # Search the entire file system for 'id_rsa' files, suppressing error messages.
	if [ -n "$rsa_keys" ]; then
		echo "id_rsa files found:"
		echo "$rsa_keys"
	else
		echo "No id_rsa files found."
	fi

	echo "#####################################"
	echo "Searching for Kernel Exploits"
	echo "Kernel Version: $(uname -a)"

	if command -v searchsploit >/dev/null 2>&1; then
		searchsploit $(uname -a | awk '{print $3}') # Use searchsploit to check for exploits related to the current kernel version.
	else
		encoded=$(curl -Gso /dev/null -w %{url_effective} --data-urlencode "q=$3" "" | cut -d'?' -f 2)
		echo "https://www.cvedetails.com/google-search-results.php?q=kernel+3.5.6#gsc.tab=0&gsc.q=${encoded}&gsc.page=1"
	fi

	echo "#####################################"
	echo "Analyzing Sudo Executable Permissions"
	sudo_rights=$(sudo -l) # Capture the output of sudo privileges.

	if [ $? -eq 0 ]; then
		echo "Successfully retrieved sudo privileges:"
		echo "$sudo_rights"
	else
		echo "Failed to retrieve sudo privileges. Ensure this script is run with sufficient permissions."
	fi

	# Check for 'env_reset' in sudo output
	if echo "$sudo_rights" | grep -q "env_reset"; then
		echo "'env_reset' parameter is set."
	else
		echo "'env_reset' parameter is not set."
	fi

	# Check for 'LD_PRELOAD' in the 'env_keep' list
	if echo "$sudo_rights" | grep -q "env_keep.*LD_PRELOAD"; then
		echo "LD_PRELOAD is preserved in 'env_keep'."
	else
		echo "LD_PRELOAD is not preserved in 'env_keep'."
	fi

	echo "#####################################"
	echo "Searching for Exploits in Sudo Version"

	SVERSION=$(sudo -V | head -1 | awk '{print $3}')                                  # Get the sudo version.
	version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"; } # Function to compare versions.

	if version_gt "1.8.28" "$SVERSION"; then
		echo "/!\ Vulnerability to CVE-2019-14287" # Check for specific CVEs.
	fi
	if version_gt "1.8.26" "$SVERSION"; then
		echo "/!\ Vulnerability to CVE-2019-16634" #Check for specific CVEs.
	fi

	echo "#####################################"
	echo "Searching for SUID / GUID Binaries Overview"

	find / -perm -u=s -type f 2>/dev/null | xargs ls -l
	find / -perm -g=s -type f 2>/dev/null | xargs ls -l
	find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
	find / -uid 0 -perm -4000 -type f 2>/dev/null

	echo "/!\ Look for any binaries that seem odd. Any binaries running from a user's home directory?"
	echo "/!\ Check the version of any odd binaries and see if there are any public exploits that can be used to gain root."

	echo "#####################################"
	echo "Enumerating Cron Jobs"
	echo "Listing current user's cron jobs:"
	crontab -l
	echo

	echo "Listing contents of /etc/init.d:"
	ls /etc/init.d
	echo

	echo "Listing the main crontab file:"
	ls /etc/crontab
	echo

	for dir in allow d deny daily monthly weekly yearly; do
		echo "Listing $dir cron jobs:"
		ls /etc/cron.$dir
		echo
	done

	# Using an array to store paths already listed
	already_listed=("/etc/cron.yearly" "/etc/crontab" "/etc/cron.allow" "/etc/cron.deny" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")

	# Listing all cron-related files and directories but exclude already listed
	echo "Listing all other cron-related files and directories:"
	for path in /etc/cron*; do
		if [[ ! " ${already_listed[@]} " =~ " ${path} " ]]; then
			ls -d $path
		fi
	done

	echo
	echo "#####################################"
	echo "End of the audit"
	echo "#####################################"
	echo "#####################################"
}

main
