#!/bin/bash

#
# Copyright 2004 - 2013 Wayne Grant
#           2013 - 2025 Kai Kramer
#
# This file is part of KeyStore Explorer.
#
# KeyStore Explorer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# KeyStore Explorer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
#
#

set +x -euo pipefail

if [[ -z "${VT_API_KEY}" ]]; then
  echo "::error::VT_API_KEY environment variable is not set."
  exit 1
fi

if [[ -z "${GITHUB_TOKEN}" ]]; then
  echo "::error::GITHUB_TOKEN environment variable is not set."
  exit 1
fi

if [[ $# -eq 0 ]]; then
  echo "::warning::No files provided for scanning."
  exit 0
fi

VT_API_URL="https://www.virustotal.com/api/v3"
ANALYSIS_LINKS=""

echo "Working dir: ${PWD}"

for file_path in "$@"; do
  if [[ ! -f "${file_path}" ]]; then
    echo "::warning::File not found: ${file_path}"
    continue
  fi

  echo "Uploading ${file_path} to VirusTotal..."
  file_name=$(basename "${file_path}")
  file_size=$(stat -c%s "${file_path}")

  # For files larger than 32MB, get a specific upload URL
  if (( file_size > 33554432 )); then
    echo "File is larger than 32MB, getting a dedicated upload URL."
    upload_url=$(curl -s --request GET --url "${VT_API_URL}/files/upload_url" --header "x-apikey: ${VT_API_KEY}" | jq -r '.data')
  else
    upload_url="${VT_API_URL}/files"
  fi

  response=$(curl -s --request POST \
    --url "${upload_url}" \
    --header "x-apikey: ${VT_API_KEY}" \
    --form "file=@${file_path}")

  analysis_id=$(echo "${response}" | jq -r '.data.id')

  if [[ -z "${analysis_id}" || "${analysis_id}" == "null" ]]; then
    error_message=$(echo "${response}" | jq -r '.error.message')
    echo "::error::Failed to get analysis ID for ${file_name}. Error: ${error_message:-Unknown error}"
    continue
  fi

  analysis_url="https://www.virustotal.com/gui/file-analysis/${analysis_id}"
  echo "Scan submitted for ${file_name}: ${analysis_url}"
  ANALYSIS_LINKS+="- **${file_name}**: [VirusTotal Analysis](${analysis_url})\\n"
done

if [[ -z "${ANALYSIS_LINKS}" ]]; then
  echo "No files were successfully submitted for scanning."
  exit 0
fi

echo "Updating GitHub release body..."

GH_API_URL="https://api.github.com"
RELEASE_URL="${GH_API_URL}/repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}"

release_data=$(curl -s -H "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/vnd.github.v3+json" "${RELEASE_URL}")
release_body=$(echo "${release_data}" | jq -r '.body')
release_id=$(echo "${release_data}" | jq -r '.id')

if [[ -z "${release_id}" || "${release_id}" == "null" ]]; then
    echo "::warning::Could not find release with tag ${GITHUB_REF_NAME} - aborting update."
    exit 0
fi

# Append new links to the existing body
new_body=$(printf "%s\\n\\n---\\n\\n**VirusTotal Scans**:\\n%b" "${release_body}" "${ANALYSIS_LINKS}")

# Create JSON payload for PATCH request
json_payload=$(jq -n --arg body "$new_body" '{body: $body}')

# Update the release
curl -s --request PATCH \
  --url "${GH_API_URL}/repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
  --header "Authorization: token ${GITHUB_TOKEN}" \
  --header "Content-Type: application/json" \
  --data "${json_payload}"

echo "Successfully updated release body."
