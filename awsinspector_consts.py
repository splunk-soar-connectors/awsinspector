# File: awsinspector_consts.py
#
# Copyright (c) 2019-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Define your constants here
AWSINSPECTOR_INVALID_LIMIT = "Please provide non-zero positive integer in limit"
AWSINSPECTOR_MAX_PER_PAGE_LIMIT = 500
AWSINSPECTOR_JSON_REGION = "region"
AWSINSPECTOR_REGION_DICT = {
    "US East (N. Virginia)": "us-east-1",
    "US East (Ohio)": "us-east-2",
    "US West (N. California)": "us-west-1",
    "US West (Oregon)": "us-west-2",
    "Asia Pacific (Mumbai)": "ap-south-1",
    "Asia Pacific (Seoul)": "ap-northeast-2",
    "Asia Pacific (Singapore)": "ap-southeast-1",
    "Asia Pacific (Sydney)": "ap-southeast-2",
    "Asia Pacific (Tokyo)": "ap-northeast-1",
    "EU (Frankfurt)": "eu-central-1",
    "EU (Ireland)": "eu-west-1",
    "EU (London)": "eu-west-2",
}
AWSINSPECTOR_BAD_ASSET_CONFIG_MSG = "Please provide access keys or select assume role check box in asset configuration"
AWSINSPECTOR_ROLE_CREDENTIALS_FAILURE_MSG = "Failed to retrieve EC2 role credentials from instance"
AWSINSPECTOR_DEFAULT_TIMEOUT = 30
