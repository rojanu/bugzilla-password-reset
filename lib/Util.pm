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
# The Initial Developer of the Original Code is Ali Ustek
# Portions created by the Initial Developer are Copyright (C) 2011 the
# Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ali Ustek <aliustek@gmail.com>

package Bugzilla::Extension::PasswordReset::Util;
use strict;
use base qw(Exporter);
our @EXPORT = qw( send_password_notification_email );

use Bugzilla::Mailer;
use Date::Format;
use Date::Parse;

# Number of days before sending warning for password changing
use constant PASSWORD_RESET_WARN_DAYS  => 14;
# Number of day intervals to send password warnings
use constant PASSWORD_WARN_FREQ_DAYS  => 3;

# This file can be loaded by your extension via 
# "use Bugzilla::Extension::PasswordReset::Util". You can put functions
# used by your extension in here. (Make sure you also list them in
# @EXPORT.)

sub send_password_notification_email {
    print "In Send\n";
    my $reset_period = Bugzilla->params->{'password_reset_period'};
    return if !$reset_period;
    print "Checking passwords\n";
    my $dbh = Bugzilla->dbh;
    my $warn_days = PASSWORD_RESET_WARN_DAYS;
    my $warn_freq_days = PASSWORD_WARN_FREQ_DAYS;
    if ($reset_period < ($warn_days * 2)) {
        $warn_days = int($reset_period / 2);
    }

    my $warn_barier = $reset_period - $warn_days;
    my $query = "SELECT login_name FROM profiles 
                    WHERE disabledtext = ''
                    AND disable_mail != 1
                    AND (extern_id IS NULL OR extern_id = '')
                    AND ".$dbh->sql_date_format("password_changed", "%Y%m%d")." = ".
                   $dbh->sql_date_format($dbh->sql_date_math('LOCALTIMESTAMP(0)', '-', '?', 'DAY'), "%Y%m%d");
    print "Reset Query: ". $query ."\n";
    print "Warn users of password reset:\n";
    # Warn users of password reset
    while ($warn_days >= 0) {
        $warn_days = $warn_freq_days if($warn_days > 0 && $warn_days < $warn_freq_days);
        # Fetch all users to be warned and send an email
        my $warn_users = $dbh->selectcol_arrayref($query, undef, $warn_barier);
        print $warn_days . " Days remaining:\n";
        foreach my $recipient (@$warn_users) {
            print "\t$recipient\n";
            my $message;
            my $template = Bugzilla->template;
            $template->process('email/password-change-notification.txt.tmpl',
                               { to => $recipient.Bugzilla->params->{'emailsuffix'},
                                 days => $warn_days},
                               \$message)
                || ThrowTemplateError($template->error());
            MessageToMTA($message);
        }
        # Move to next warn interval
        $warn_days = $warn_days - $warn_freq_days;
        $warn_barier = $reset_period - $warn_days;
    }

    # Warn users of password expiry
    # Fetch all users with expired passwords and reset passwords and send an email
    $query = "SELECT userid, login_name FROM profiles 
                    WHERE disabledtext = ''
                    AND disable_mail != 1
                    AND (extern_id IS NULL OR extern_id = '')
                    AND cryptpassword != '*'
                    AND password_changed <".
                   $dbh->sql_date_math('LOCALTIMESTAMP(0)', '-', '?', 'DAY');
    print "Expiry Query: ". $query ." " > $reset_period ."\n";
    my $reset_users = $dbh->selectall_arrayref($query, undef, $reset_period);
    my $cryptedpassword = '*';
    print "Warn users of password expiry:\n";
    foreach my $row (@$reset_users) {
        my ($userid, $recipient) = @$row;
        print "\t$recipient\n";
        Bugzilla->dbh->do(q{UPDATE profiles
                      SET cryptpassword = ?,
                          password_changed = LOCALTIMESTAMP(0)
                      WHERE userid = ?},
                      undef, ($cryptedpassword, $userid));
        # Logout the user to force password change
        Bugzilla->logout_user_by_id($userid);

        my $message;
        my $template = Bugzilla->template;
        $template->process('email/password-reset-notification.txt.tmpl',
                          {to => $recipient.Bugzilla->params->{'emailsuffix'}},
                           \$message)
                           || ThrowTemplateError($template->error());
        MessageToMTA($message);
    }
}

1;
