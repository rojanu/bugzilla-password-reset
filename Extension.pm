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

package Bugzilla::Extension::PasswordReset;
use strict;
use base qw(Bugzilla::Extension);

use Bugzilla::User;
use Bugzilla::Config::Common;
use Bugzilla::Extension::PasswordReset::Util;

our $VERSION = '0.01';

BEGIN {
   *Bugzilla::User::password_changed = \&password_changed;
   *Bugzilla::User::set_password_history = \&set_password_history;
   *Bugzilla::User::check_password_history = \&check_password_history;
   *Bugzilla::User::needs_password_change = \&needs_password_change;
}

###########################
# Database & Installation #
###########################

sub install_update_db {
    my $dbh = Bugzilla->dbh;
    
    my $current_time = $dbh->selectrow_array('SELECT LOCALTIMESTAMP(0)');
    $dbh->bz_add_column('profiles', 'password_changed',
                        { TYPE => 'DATETIME', NOTNULL => 1}, $current_time);
}

sub db_schema_abstract_schema {
    my ($self, $args) = @_;
    $args->{'schema'}->{'password_history'} = {
        FIELDS => [
            pass_id       => {TYPE => 'MEDIUMSERIAL', NOTNULL => 1,
                              PRIMARYKEY => 1},
            userid        => {TYPE => 'INT3', NOTNULL => 1,
                              REFERENCES => {TABLE  => 'profiles', 
                                             COLUMN => 'userid',
                                             DELETE => 'CASCADE'}},
            password      => {TYPE => 'varchar(128)', NOTNULL => 1},
        ],
        INDEXES => [
            profiles_password_userid_idx  => ['userid'],
        ],
    };
}

###########
# Objects #
###########

sub object_columns {
    my ($self, $args) = @_;
    my ($class, $columns) = @$args{qw(class columns)};

    if ($class->isa('Bugzilla::User')) {
        push(@$columns, 'profiles.password_changed');
    }
}

##########
# Config #
##########

sub config_modify_panels {
    my ($self, $args) = @_;
    my $panels = $args->{panels};
    my $auth_params = $panels->{'auth'}->{params};
    
    push(@$auth_params, { name => 'password_history_length',
                          type => 't',
                          default => 0,
                          checker => \&check_numeric });
                          
    push(@$auth_params, { name => 'password_reset_period',
                          type => 't',
                          default => 0,
                          checker => \&check_numeric });
}

#######################
# User Object Methods #
#######################

sub password_changed { ($_[0]->{password_changed}); }
sub set_password_history {
    my $self = shift;
    my $password_history_length = Bugzilla->params->{password_history_length};
    my $dbh = Bugzilla->dbh;

    if ($password_history_length) {
        # Delete all except last $password_history_length-1 passwords
        # to make sure with the latest one we are on $password_history_length
        my $pass_ids = $dbh->selectcol_arrayref(q{SELECT pass_id FROM
                            password_history WHERE userid=? 
                            ORDER BY pass_id DESC LIMIT ?},
                            undef, ($self->id, $password_history_length-1));
        if (@$pass_ids) {
            $dbh->do('DELETE FROM password_history WHERE pass_id NOT IN ('.
                                                   join(',', @$pass_ids) .')');
        }
        
        # insert newly changed password into database
        $dbh->do(q{INSERT INTO password_history (userid, password)
                     VALUES (?,?)}, undef, ($self->id, $self->cryptpassword));
    }
    else {
        # Delete passwords history for all users
        $dbh->do('DELETE FROM password_history');
    }
}

sub check_password_history {
    my ($self, $new_password) = @_;
    my $password_history_length = Bugzilla->params->{password_history_length};
    return unless $password_history_length;

    my $password_list = Bugzilla->dbh->selectcol_arrayref(
          "SELECT password FROM password_history ".
          "WHERE userid=? ORDER BY pass_id DESC LIMIT ?",
          undef, ($self->id, $password_history_length));

    foreach my $old_password_crypt (@$password_list) {
        if (bz_crypt($new_password, $old_password_crypt) eq $old_password_crypt) {
            ThrowUserError("passwords_match_old",
                { 'password_history_length' => $password_history_length });
        }
    }
}

sub needs_password_change {
    my ($self) = @_;
    return 0 unless $self->id && Bugzilla->params->{'password_reset_period'};

    my $elapsed_days = (time() - str2time($self->password_changed))/86400;

    return $elapsed_days >= Bugzilla->params->{'password_reset_period'} ? 1 : 0;
}

__PACKAGE__->NAME;
