package OAuth::Lite2::Server::GrantHandler::GroupingRefreshToken;
use strict;
use warnings;
use parent 'OAuth::Lite2::Server::GrantHandler';

use Carp ();
use OAuth::Lite2::Util qw(
    is_equal_or_down_scope
);
use OAuth::Lite2::Server::Error;
use OAuth::Lite2::ParamMethod::AuthHeader;

sub handle_request {
    my ($self, $dh) = @_;

    my $req = $dh->request;

    my $parser = OAuth::Lite2::ParamMethod::AuthHeader->new;
    my $header_credentials = $parser->basic_credentials($req);
    my $client_id = ($header_credentials->{client_id}) ? $header_credentials->{client_id} : $req->param("client_id");

    OAuth::Lite2::Server::Error::UnauthorizedClient->throw(
        description => "'client_id' is not allowed to issue grouping_refresh_token"
    )   unless  $dh->is_allowed_client_to_issue_grouping_refresh_token($client_id);

    # validate refresh_token
    my $refresh_token = $req->param("refresh_token")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'refresh_token' not found"
        );

    my $auth_info = $dh->get_auth_info_by_refresh_token($refresh_token)
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'refresh_token' is invalid"
        );
    Carp::croak "OAuth::Lite2::Server::DataHandler::get_auth_info_by_refresh_token doesn't return OAuth::Lite2::Model::AuthInfo"
        unless ($auth_info
            && $auth_info->isa("OAuth::Lite2::Model::AuthInfo"));

    OAuth::Lite2::Server::Error::InvalidClient->throw(
        description => "'client_id' doesn't match refresh_token"
    )   unless $auth_info->client_id eq $client_id;

    my $group_id = $dh->get_group_id_by_client_id( $client_id )
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'client_id' does not have group id"
        );

    # validate target client
    my $target_client_id = $req->param("target_client_id")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'target_client_id' not found"
        );

    my $target_package_id = $req->param("target_package_id")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'target_package_id' not found"
        );

    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "invalid target client"
    )   unless  $dh->validate_client_package(
                    client_id   => $target_client_id,
                    package_id  => $target_package_id,
                );

    my $target_group_id = $dh->get_group_id_by_client_id( $target_client_id )
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'target_client_id' does not have group id"
        );

    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "group id does not match"
    )   unless  ( $group_id eq $target_group_id );

    my $scope = $req->param("scope");
    OAuth::Lite2::Server::Error::InvalidScope->throw
        unless $dh->validate_grouping_scope( $target_client_id, $scope );

    # allow only equal or down scope
    OAuth::Lite2::Server::Error::InsufficientScope->throw
        unless is_equal_or_down_scope ( $auth_info->scope, $scope );

    # create response 
    my $grouping_auth_info =    $dh->create_or_update_auth_info(
                                    client_id       => $target_client_id,
                                    user_id         => $auth_info->user_id,
                                    scope           => $scope,
                                );
    Carp::croak "OAuth::Lite2::Server::DataHandler::create_or_update_auth_info doesn't return OAuth::Lite2::Model::AuthInfo"
        unless ($grouping_auth_info
            && $grouping_auth_info->isa("OAuth::Lite2::Model::AuthInfo"));

    my $res = {
        refresh_token => $grouping_auth_info->refresh_token,
    };
    $res->{scope} = $grouping_auth_info->scope
        if $grouping_auth_info->scope;

    return $res;
}

=head1 NAME

OAuth::Lite2::Server::GrantHandler::GroupingRefreshToken - handler for 'grouping-refresh-token' grant_type request

=head1 SYNOPSIS

    my $handler = OAuth::Lite2::Server::GrantHandler::GroupingRefreshToken->new;
    my $res = $handler->handle_request( $data_handler );

=head1 DESCRIPTION

handler for 'grouping-refresh-token' grant_type request.

=head1 METHODS

=head2 handle_request( $req )

See L<OAuth::Lite2::Server::GrantHandler> document.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
