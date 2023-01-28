<?php

add_action('rest_api_init', 'wp_rest_user_endpoints');
function wp_rest_user_endpoints($request)
{
    register_rest_route('auth', 'users/register', array(
        'methods' => 'POST',
        'callback' => 'register_user_endpoint_handler',
    ));
}


// New user registration endpoint handler
function register_user_endpoint_handler($request = null)
{
    $response = array();
    $parameters = $request->get_body_params();
    $username = sanitize_text_field($parameters['username']);
    $email = sanitize_text_field($parameters['email']);
    $password = sanitize_text_field($parameters['password']);
    if (is_user_logged_in()) {
        // Administrator can register users
        $logged_user = wp_get_current_user();
        $logged_user_role = $logged_user->roles[0];
        if ($logged_user_role == 'administrator') {
            $role = sanitize_text_field($parameters['role']);
        }
    }
    $error = new WP_Error();
    if (empty($username)) {
        $error->add(400, __("Username field 'username' is required.", 'wp-rest-user'), array('status' => 400));
        return $error;
    }
    if (empty($email)) {
        $error->add(401, __("Email field 'email' is required.", 'wp-rest-user'), array('status' => 400));
        return $error;
    }
    if (empty($password)) {
        $error->add(404, __("Password field 'password' is required.", 'wp-rest-user'), array('status' => 400));
        return $error;
    }

    if (is_user_logged_in()) {
        // Administrator can register users
        $logged_user = wp_get_current_user();
        $logged_user_role = $logged_user->roles[0];
        if ($logged_user_role == 'administrator') {
            if (empty($role)) {
                $error->add(405, __("Role field 'role' is not a valid. Check your User Roles from Dashboard.", 'wp_rest_user'), array('status' => 400));
                return $error;
            }
        }
    }
    $user_id = username_exists($username);
    if (!$user_id && email_exists($email) == false) {
        $user_id = wp_create_user($username, $password, $email);
        if (!is_wp_error($user_id)) {
            // Ger User Meta Data (Sensitive, Password included. DO NOT pass to front end.)
            $user = get_user_by('id', $user_id);
            if (is_user_logged_in()) {
                // Administrator can register users
                $logged_user = wp_get_current_user();
                $logged_user_role = $logged_user->roles[0];
                if ($logged_user_role == 'administrator') {
                    $user->set_role($role);
                }
            } else {
                $user->set_role('subscriber');
            }

            // Ger User Data (Non-Sensitive, Pass to front end.)
            $response['code'] = 200;
            $response['message'] = __("User '" . $username . "' Registration was Successful", "wp-rest-user");
        } else {
            return $user_id;
        }
    } else {
        $error->add(406, __("Email already exists, please try 'Reset Password'", 'wp-rest-user'), array('status' => 400));
        return $error;
    }
    return new WP_REST_Response($response, 123);
}
