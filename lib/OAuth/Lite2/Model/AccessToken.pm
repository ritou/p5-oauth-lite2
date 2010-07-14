package OAuth::Lite2::Model::AccessToken;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    auth_id
    token
    expires_in
    secret
    secret_type
    created_on
));

=head1 NAME

OAuth::Lite2::Model::AccessToken - model class that represents access token

=head1 ACCESSORS

=head2 auth_id

Identifier of L<OAuth::Lite2::Model::AuthInfo>.

=head2 token

Access token string.

=head2 expires_in

Seconds to expires from 'created_on'

=head2 created_on

UNIX time when access token created.

=head2 secret

DEPRECATED.

=head2 secret_type

DEPRECATED.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

