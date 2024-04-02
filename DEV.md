<!--
SPDX-FileCopyrightText: 2024 Federal Office of Information Technology, Systems and Telecommunication FOITT
SPDX-FileCopyrightText: 2024 Swiss Confederation

SPDX-License-Identifier: MIT
-->

# Code Helpers 

## How to update license and copyright info
We use [REUSE](https://reuse.software/) to manage the license.  

You may use the following command in a dev environment at root level to update license data:
``` bash
  poetry run reuse annotate -r --fallback-dot-license --merge-copyrights \
    --license "MIT" \
    --year "2024" \
    --copyright "Swiss Confederation" \
    . 
```
