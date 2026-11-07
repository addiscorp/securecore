<?php
// Marshalling WordPress objects across the socket, shared by both ends (SecureCore.php in
// core and sandbox/realwp.php in the child). unserialize() on the wire forbids classes, so an
// object cannot cross as itself. Instead each side encodes the common WordPress objects as
// small markers and the other rebuilds them from its own WordPress: a post by id, the main
// query and the $wp object from globals, a user/term by id. Both ends run a full WordPress,
// so the same marker rebuilds to the equivalent object on each — which is how a callback in
// the sandbox comes to work on the same post/query/user that core resolved.
//
// What does not cross: an object we do not recognise becomes null (logged by core as a
// mirror/throw, not fatal). This is the request-state boundary the spike reports on.
namespace SecureCore;

/** Encode a value for the wire: WordPress objects → markers; closures → null; arrays recurse. */
function marshal_encode(mixed $value): mixed
{
    if (is_object($value)) {
        if ($value instanceof \Closure) return null;
        if ($value instanceof \WP_Post) return ['__sc' => 'post', 'id' => $value->ID];
        if ($value instanceof \WP_User) return ['__sc' => 'user', 'id' => $value->ID];
        if ($value instanceof \WP_Term) return ['__sc' => 'term', 'id' => $value->term_id];
        if ($value instanceof \WP_Query) return ['__sc' => 'query'];
        if (class_exists('WP', false) && $value instanceof \WP) return ['__sc' => 'wp'];
        if (class_exists('WP_Screen', false) && $value instanceof \WP_Screen) {
            return ['__sc' => 'screen', 'id' => $value->id, 'base' => $value->base, 'post_type' => $value->post_type, 'taxonomy' => $value->taxonomy, 'action' => $value->action];
        }
        if ($value instanceof \WP_REST_Request) {
            return ['__sc' => 'rest_request', 'method' => $value->get_method(), 'route' => $value->get_route(),
                'get' => $value->get_query_params(), 'post' => $value->get_body_params(), 'json' => $value->get_json_params() ?: [],
                'files' => $value->get_file_params(), 'url' => $value->get_url_params(), 'headers' => $value->get_headers(), 'body' => $value->get_body()];
        }
        if ($value instanceof \WP_REST_Response) {
            return ['__sc' => 'rest_response', 'data' => marshal_encode($value->get_data()), 'status' => $value->get_status(), 'headers' => $value->get_headers()];
        }
        if ($value instanceof \WP_Error) {
            return ['__sc' => 'error', 'code' => $value->get_error_code(), 'message' => $value->get_error_message(), 'data' => $value->get_error_data()];
        }
        if (class_exists('WP_Admin_Bar', false) && $value instanceof \WP_Admin_Bar) {
            // The admin bar is passed by reference for callbacks to add nodes to. Those nodes
            // cannot reach core's bar across the socket (a spike limit), but the callback must
            // get a real object, not null; the other side hands it a throwaway bar.
            return ['__sc' => 'admin_bar'];
        }
        return null; // unknown object: best effort, cannot cross
    }
    if (is_array($value)) {
        $out = [];
        foreach ($value as $k => $v) $out[$k] = marshal_encode($v);
        return $out;
    }
    return $value;
}

/**
 * Decode a value from the wire: markers → objects rebuilt from this side's WordPress;
 * callback references → a stub made by $makeStub(id); arrays recurse.
 */
function marshal_decode(mixed $value, ?callable $makeStub = null): mixed
{
    if (!is_array($value)) return $value;
    if (isset($value['__sc'])) return marshal_reconstruct($value);
    if (count($value) === 1 && array_key_exists('__securecore_callback', $value)) {
        return $makeStub ? $makeStub((int) $value['__securecore_callback']) : null;
    }
    $out = [];
    foreach ($value as $k => $v) $out[$k] = marshal_decode($v, $makeStub);
    return $out;
}

function marshal_reconstruct(array $m): mixed
{
    switch ($m['__sc']) {
        case 'post':
            return get_post((int) $m['id']);
        case 'user':
            return get_userdata((int) $m['id']) ?: new \WP_User((int) $m['id']);
        case 'term':
            $term = get_term((int) $m['id']);
            return $term instanceof \WP_Term ? $term : null;
        case 'query':
            return $GLOBALS['wp_query'] ?? null;
        case 'wp':
            return $GLOBALS['wp'] ?? null;
        case 'screen':
            return function_exists('convert_to_screen') ? convert_to_screen($m['id'] ?? 'front') : null;
        case 'rest_request':
            $r = new \WP_REST_Request($m['method'] ?? 'GET', $m['route'] ?? '');
            foreach (($m['headers'] ?? []) as $name => $vals) $r->set_header($name, is_array($vals) ? implode(',', $vals) : $vals);
            $r->set_query_params($m['get'] ?? []);
            $r->set_body_params($m['post'] ?? []);
            $r->set_url_params($m['url'] ?? []);
            $r->set_file_params($m['files'] ?? []);
            if (!empty($m['json'])) { $r->set_header('content-type', 'application/json'); $r->set_body(wp_json_encode($m['json'])); }
            elseif (!empty($m['body'])) $r->set_body($m['body']);
            return $r;
        case 'rest_response':
            $response = new \WP_REST_Response(marshal_decode($m['data'] ?? null), $m['status'] ?? 200);
            if (!empty($m['headers'])) $response->set_headers($m['headers']);
            return $response;
        case 'error':
            return new \WP_Error($m['code'] ?? 'error', $m['message'] ?? '', $m['data'] ?? '');
        case 'admin_bar':
            return class_exists('WP_Admin_Bar') ? new \WP_Admin_Bar() : null;
    }
    return null;
}
