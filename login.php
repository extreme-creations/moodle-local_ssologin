<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Handles SSO login requests.
 *
 * @package    local_ssologin
 * @copyright  2025 Richard Guedes  - Instituto de Defesa Cibernética (IDCiber)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require('../../config.php');
require_once($CFG->libdir . '/authlib.php');
require_once(__DIR__.'/locallib.php');

// Ensure the user is logged in or has appropriate permissions.
// START EXTREME EDIT - original code will 303 redirect if a user is not already logged in. Makes the plugin a bit pointless if you can't proceed.
// require_login();
// END EXTREME EDIT

$secret = get_config('local_ssologin', 'secretkey');
$tokenexpire = get_config('local_ssologin', 'tokenexpire');

$encdata = required_param('data', PARAM_RAW);
$signature = required_param('sig', PARAM_ALPHANUMEXT);

$data = local_ssologin_decrypt($encdata, $secret);
$payload = json_decode($data, true);

if (!local_ssologin_verify_token($data, $signature, $secret)) {
    throw new moodle_exception('invalidtoken', 'local_ssologin');
}

if (time() - $payload['timestamp'] > $tokenexpire) {
    throw new moodle_exception('invalidtoken', 'local_ssologin');
}

// START EXTREME EDIT
$user = null;
$username = $payload['username'] ?? null;
$email = $payload['email'] ?? null;

// Try to find user by email first if provided in payload.
if ($email) {
    if ($user = $DB->get_record('user', ['email' => $email, 'deleted' => 0])) {
        $username = $user->username;
    }
}

// Fallback to username search if email match not found and username exists.
if (!$user && $username) {
    $user = $DB->get_record('user', ['username' => $username, 'deleted' => 0]);
}

if ($user) {
    complete_user_login($user);
    local_ssologin_log_attempt('success', $user->id, $username);

    if ($redirectQuery = optional_param('redirect', null, PARAM_URL)) {
        redirect($redirectQuery);
    }

    redirect(new moodle_url('/'));
} else {
    local_ssologin_log_attempt('fail', 0, $username ?? $email);
    throw new moodle_exception('loginfailure', 'local_ssologin', '', $username ?? $email);
}
// END EXTREME EDIT
