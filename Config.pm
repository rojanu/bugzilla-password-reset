# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the PasswordReset Bugzilla Extension.
#
# The Initial Developer of the Original Code is YOUR NAME
# Portions created by the Initial Developer are Copyright (C) 2011 the
# Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   YOUR NAME <YOUR EMAIL ADDRESS>

package Bugzilla::Extension::PasswordReset;
use strict;

use constant NAME => 'PasswordReset';

use constant REQUIRED_MODULES => [
    {
        package => 'Date-Parse',
        module  => 'Date::Parse',
        version => 0,
    },
    {
        package => 'Date-Format',
        module  => 'Date::Format',
        version => 0,
    },
];

use constant OPTIONAL_MODULES => [
];

__PACKAGE__->NAME;