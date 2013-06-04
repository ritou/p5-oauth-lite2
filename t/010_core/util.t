use strict;
use warnings;

use Test::More tests => 19;

use OAuth::Lite2::Util qw(
    encode_param
    decode_param
    parse_content
    build_content
    is_equal_or_down_scope
);

use Hash::MultiValue;

TEST_ENCODE: {

my $param = q{123 @#$%&hoge hoge+._-~};
my $encoded = encode_param($param);
is($encoded, q{123%20%40%23%24%25%26hoge%20hoge%2B._-~});
my $decoded = decode_param($encoded);
is($decoded, $param);

};

TEST_PARSE_CONTENT: {
    my $content = q{aaa=bbb&bbb=ccc&ddd=eee&aaa=ddd};
    my $params  = parse_content($content);
    is($params->{bbb}, 'ccc');
    is($params->get('bbb'), 'ccc');
    ok(!$params->get('fff'));
    is($params->get('aaa'), 'ddd');
    my @aaa = $params->get_all('aaa');
    is(scalar @aaa, 2);
    is($aaa[0], 'bbb');
    is($aaa[1], 'ddd');
};

TEST_BUILD_CONTENT: {
    my $params = {
        aaa => 'bbb',
        bbb => 'ccc',
        ccc => 'ddd',
        ddd => ['eee', 'fff'],
    };
    my $content = build_content($params);
    is($content, 'aaa=bbb&bbb=ccc&ccc=ddd&ddd=eee&ddd=fff');
    $params = Hash::MultiValue->new(
        aaa => 'bbb',
        bbb => 'ccc',
        ccc => 'ddd',
        ddd => 'eee',
        ddd => 'fff',
    );
    $content = build_content($params);
    is($content, 'aaa=bbb&bbb=ccc&ccc=ddd&ddd=eee&ddd=fff');
};

TEST_IS_EQUAL_OR_DOWN_SCOPE: {
    my ($src_scope, $dst_scope, $result);

    $src_scope = "";
    $dst_scope = "";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( $result, q{src and dst are empty});

    $src_scope = "aaa";
    $dst_scope = "aaa";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( $result, q{scope is equal});

    $src_scope = "aaa bbb";
    $dst_scope = "bbb aaa";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( $result, q{scope is equal});

    $src_scope = "aaa";
    $dst_scope = "";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( $result, q{dst_scope is empty});

    $src_scope = "bbb aaa";
    $dst_scope = "aaa";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( $result, q{dst_scope is down});

    $src_scope = "";
    $dst_scope = "aaa";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( !$result, q{src_scope is empty});
    
    $src_scope = "aaa";
    $dst_scope = "bbb aaa";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( !$result, q{dst_scope is wide});

    $src_scope = "aaa bbb";
    $dst_scope = "bbb ccc";
    $result = is_equal_or_down_scope( $src_scope, $dst_scope);
    ok( !$result, q{dst_scope is wide});
};
