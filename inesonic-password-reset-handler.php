<?php
/**
 * Plugin Name: Inesonic Password Reset Handler
 * Plugin URI: http://www.inesonic.com
 * Description: A small proprietary plug-in that provides support for password reset.
 * Version: 1.0.0
 * Author: Inesonic, LLC
 * Author URI: http://www.inesonic.com
 */

/***********************************************************************************************************************
 * Copyright 2022, Inesonic, LLC.
 *
 * GNU Public License, Version 3:
 *   This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
 *   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
 *   later version.
 *   
 *   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *   details.
 *   
 *   You should have received a copy of the GNU General Public License along with this program.  If not, see
 *   <https://www.gnu.org/licenses/>.
 ***********************************************************************************************************************
 */

require_once "vendor/autoload.php";

/**
 * Inesonic password reset handler plug-in
 */
class InesonicPasswordResetHandler {
    const VERSION = '1.0.0';
    const SLUG    = 'inesonic-password-reset-handler';
    const NAME    = 'Inesonic Password Reset Handler';
    const AUTHOR  = 'Inesonic, LLC';
    const PREFIX  = 'InesonicPasswordResetHandler';

    /**
     * The plug-in template directory
     */
    const TEMPLATE_DIRECTORY = __DIR__ . '/templates/';

    /**
     * The slug to direct to in order to reset a user password.
     */
    const REQUEST_PASSWORD_RESET_SLUG = "reset-password";

    /**
     * The password reset successful page slug.
     */
    const PASSWORD_RESET_SUCCESSFUL_SLUG = "password-reset-successful";

    /**
     * The password reset failed page slug.
     */
    const PASSWORD_RESET_FAILED_SLUG = "password-reset-failed";

    /**
     * The reset password page slug.
     */
    const PASSWORD_RESET_SLUG = "/password-reset/";

    /**
     * Maximum lifespan for password reset keys, in seconds.
     */
    const PASSWORD_RESET_KEY_MAXIMUM_AGE = 12 * 60 * 60;

    /**
     * The plug-in singleton instance.
     */
    private static $instance;  /* Plug-in instance */

    /**
     * Method that is called to initialize a single instance of the plug-in
     */
    public static function instance() {
        if (!isset(self::$instance)                                           &&
            !(self::$instance instanceof InesonicPasswordResetHandler)    ) {
            self::$instance = new InesonicPasswordResetHandler();
            spl_autoload_register(array(self::$instance, 'autoloader'));
        }
    }

    /**
     * Static method that is triggered when the plug-in is activated.
     */
    public static function plugin_activated() {
        if (defined('ABSPATH') && current_user_can('activate_plugins')) {
            $plugin = isset($_REQUEST['plugin']) ? sanitize_text_field($_REQUEST['plugin']) : '';
            if (check_admin_referer('activate-plugin_' . $plugin)) {
                global $wpdb;
                $wpdb->query(
                    'CREATE TABLE ' . $wpdb->prefix . 'inesonic_password_reset_key' . ' (' .
                        'user_id BIGINT UNSIGNED NOT NULL,' .
                        'password_reset_key VARCHAR(64) NOT NULL,' .
                        'created BIGINT UNSIGNED NOT NULL,' .
                        'PRIMARY KEY (user_id),' .
                        'FOREIGN KEY (user_id) REFERENCES ' . $wpdb->prefix . 'users (ID) ' .
                            'ON DELETE CASCADE' .
                    ')'
                );
            }
        }
    }

    /**
     * Static method that is triggered when the plug-in is deactivated.
     */
    public static function plugin_uninstalled() {
        if (defined('ABSPATH') && current_user_can('activate_plugins')) {
            $plugin = isset($_REQUEST['plugin']) ? sanitize_text_field($_REQUEST['plugin']) : '';
            if (check_admin_referer('deactivate-plugin_' . $plugin)) {
                global $wpdb;
                $wpdb->query('DROP TABLE ' . $wpdb->prefix . 'inesonic_password_reset_key');
            }
        }
    }

    /**
     * This method ties the plug-in into the rest of the WordPress framework by adding hooks where needed.
     */
    public function __construct() {
        $this->loader               = null;
        $this->template_environment = null;

        add_action('init', array($this, 'customize_on_initialization'));
        add_filter('lostpassword_url', array($this, 'force_lost_password_url'), 1000, 2);

        add_action('inesonic-request-password-reset', array($this, 'request_password_reset'));
        add_action('inesonic-reset-user-password', array($this, 'reset_user_password'));

        add_filter('inesonic-filter-page-password-reset', array($this, 'validate_password_reset_key'));

        add_action('after_password_reset', array($this, 'report_password_reset'), 1000, 2);

        add_filter(
            'retrieve_password_notification_email',
            array($this, 'wordpress_override_password_notification_email'),
            1000,
            4
        );

        $this->create_localized_strings();
    }

    /**
     * Method that handles the PSR-4 autoload.
     *
     * \param[in] $class_name The name of the class to be loaded.
     */
    public function autoloader($class_name) {
        if (!class_exists($class_name) and (FALSE !== strpos($class_name, self::PREFIX))) {
            $class_name = str_replace(self::PREFIX, '', $class_name);
            $classes_dir = realpath(plugin_dir_path(__FILE__)) . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR;
            $class_file = str_replace('_', DIRECTORY_SEPARATOR, $class_name) . '.php';

            if (file_exists($classes_dir . $class_file)) {
                require_once $classes_dir . $class_file;
            }
        }
    }

    /**
     * Method that performs various initialization tasks during WordPress init phase.
     */
    public function customize_on_initialization() {
        if ($this->loader === null || $this->template_environment === null) {
            $this->loader = new \Twig\Loader\FilesystemLoader(self::TEMPLATE_DIRECTORY);
            $this->template_environment = new \Twig\Environment($this->loader);
        }

        add_filter('cron_schedules', array($this, 'add_custom_cron_interval'));
        add_action('inesonic-password-reset-handler-purge', array($this, 'purge_old_entries'));
        if (!wp_next_scheduled('inesonic-password-reset-handler-purge')) {
            $time = time() + 20;
            wp_schedule_event($time, 'inesonic-every-hour', 'inesonic-password-reset-handler-purge');
        }
    }

    /**
     * Method that adds custom CRON intervals for testing.
     *
     * \param[in] $schedules The current list of CRON intervals.
     *
     * \return Returns updated schedules with new CRON entries added.
     */
    public function add_custom_cron_interval($schedules) {
        $schedules['inesonic-every-hour'] = array(
            'interval' => 60 * 60,
            'display' => esc_html__('Every hour')
        );

        return $schedules;
    }

    /**
     * Method that is triggered periodically to purge old password field entries.
     */
    public function purge_old_entries() {
        global $wpdb;
        $purge_threshold = time() - self::PASSWORD_RESET_KEY_MAXIMUM_AGE;
        $wpdb->query(
            'DELETE FROM ' . $wpdb->prefix . 'inesonic_password_reset_key' . ' WHERE ' .
            'created < ' . $purge_threshold
        );
    }

    /**
     * Method that overrides WordPress' lost password URL to redirect to our preferred page.
     *
     * \param[in] $lost_password_url The current lost password URL.
     *
     * \param[in] $redirect          The path to redirect to on the next login.
     */
    public function force_lost_password_url($lost_password_url, $redirect) {
        return home_url(self::REQUEST_PASSWORD_RESET_SLUG);
    }

    /**
     * Method that is triggered to validate a user's password reset key. This method is triggered when the password
     * reset page gets loaded.
     *
     * \param[in] $page_value The current page value.
     *
     * \return Returns the new page content.  Return $page_value to cause the default page to be rendered.
     */
    public function validate_password_reset_key($page_value) {
        if (!is_user_logged_in()) {
            if (array_key_exists('key', $_GET)) {
                $password_reset_key = sanitize_text_field($_GET['key']);

                global $wpdb;
                $query = $wpdb->prepare(
                    'SELECT user_id FROM ' . $wpdb->prefix . 'inesonic_password_reset_key' . ' WHERE ' .
                        'password_reset_key = %s',
                    $password_reset_key
                );
                $results = $wpdb->get_results($query);

                if ($wpdb->num_rows == 0) {
                    $page_value = __(
                        '<p>&nbsp;</p>
                         <p>&nbsp;</p>
                         <div class="et_pb_text_inner">
                           <p align="center"
                              style="font-size: 18px; color: #006DFA; font-family: Open Sans, Arial, sans-serif"
                           >
                             Your password reset request is no longer valid.  Please try again.
                           </p>
                         </div>
                         <p>&nbsp;</p>
                         <p>&nbsp;</p>',
                        'inesonic-password-reset-handler'
                    );
                }
            } else {
                $page_value = __(
                    '<p>&nbsp;</p>
                     <p>&nbsp;</p>
                     <div class="et_pb_text_inner">
                       <p align="center"
                          style="font-size: 18px; color: #006DFA; font-family: Open Sans, Arial, sans-serif"
                       >
                         Invalid key.  Please try again.
                       </p>
                     </div>
                     <p>&nbsp;</p>
                     <p>&nbsp;</p>',
                    'inesonic-password-reset-handler'
                );
            }
        } else {
            $page_value = __(
                '<p>&nbsp;</p>
                 <p>&nbsp;</p>
                 <p align="center"
                    style="font-size: 18px; color: #006DFA; font-family: Open Sans, Arial, sans-serif"
                 >
                   You must be logged out to reset a lost password.
                 </p>
                 <p>&nbsp;</p>
                 <p>&nbsp;</p>',
                'inesonic-password-reset-handler'
            );
        }

        return $page_value;
    }

    /**
     * Method that is triggered by NinjaForms to request a new password reset.
     *
     * \param[in] $form_data The form data for the form.
     */
    public function request_password_reset($form_data) {
        if (!is_user_logged_in()) {
            $fields_by_key = $form_data['fields_by_key'];
            if (array_key_exists('identifier', $fields_by_key)) {
                $identifier_data = $fields_by_key['identifier'];
                if (array_key_exists('value', $identifier_data)) {
                    $identifier = $identifier_data['value'];

                    $user_data = get_user_by('login', $identifier);
                    if ($user_data === false) {
                        $user_data = get_user_by('email', $identifier);
                        $show_username = true;
                    } else {
                        $show_username = false;
                    }

                    if ($user_data !== false) {
                        $message = $this->generate_password_reset_email_message($user_data, $show_username);
                        $headers[] = 'Content-Type: text/html; charset=UTF-8';

                        $success = wp_mail(
                            $user_data->user_email,
                            $this->password_reset_subject,
                            $message,
                            $headers
                        );

                        if ($success) {
                            do_action(
                                'inesonic_add_history',
                                $user_data->ID,
                                'PASSWORD_RESET_REQUESTED',
                                $user_data->user_email
                            );
                        } else {
                            do_action(
                                'inesonic-logger-1',
                                'Inesonic Password Reset Handler: Failed to send reset email to ' .
                                $user_data->user_email
                            );
                        }
                    }
                }
            }
        }
    }

    /**
     * Filter method that is triggered by the user-edit form Send Reset Link button.
     *
     * \param[in] $defaults   Array holding 'to', 'subject', 'message', and 'headers' fields to be adjusted.
     *
     * \param[in] $key        The WordPress selected password reset key -- ignored.
     *
     * \param[in] $user_login The user login for this user.
     *
     * \param[in] $user_data  The WP_User user data instance.
     *
     * \return Returns the updated defaults array.  Fields that are not included will revert the the supplied default
     *         values.
     */
    public function wordpress_override_password_notification_email($defaults, $key, $user_login, $user_data) {
        return array(
            'to' => $user_data->user_email,
            'subject' => $this->password_reset_subject,
            'message' => $this->generate_password_reset_email_message($user_data, true),
            'headers' => array('Content-Type: text/html; charset=UTF-8')
        );
    }

    /**
     * Method that generates the password reset email message content.
     *
     * \param[in] $user_data     The WP_User instance for the user in question.
     *
     * \param[in] $show_username If true, the username should be included.  If false, the username should be excluded.
     *
     * \return Returns the password reset email message content.
     */
    private function generate_password_reset_email_message($user_data, $show_username) {
        global $wpdb;
        $wpdb->delete(
            $wpdb->prefix . 'inesonic_password_reset_key',
            array('user_id' => $user_data->ID)
        );

        do {
            $sequence = openssl_random_pseudo_bytes(48);
            $password_reset_key = str_replace(
                ['+', '/', '='],
                ['-', '_', ''],
                base64_encode($sequence)
            );
            $password_reset_key = substr($password_reset_key, 0, 64);
        } while ($wpdb->get_row(
                     'SELECT user_id FROM ' . $wpdb->prefix . 'inesonic_password_reset_key ' .
                         'WHERE password_reset_key = \'' . $password_reset_key . '\''
                 ) !== null
                );

        $wpdb->insert(
            $wpdb->prefix . 'inesonic_password_reset_key',
            array(
                'user_id' => $user_data->ID,
                'password_reset_key' => $password_reset_key,
                'created' => time()
            )
        );

        $reset_url = site_url(self::PASSWORD_RESET_SLUG) . "?" .
                     http_build_query(array('key' => $password_reset_key));

        $message = $this->template_environment->render(
            $this->password_reset_template,
            array(
                'user_login' => $user_data->user_login,
                'user_email' => $user_data->user_email,
                'show_username' => $show_username,
                'site_url' => site_url(),
                'reset_url' => $reset_url
            )
        );

        return $message;
    }

    /**
     * Method that is triggered by NinjaForms to reset a user's password.
     *
     * \param[in] $form_data The NinjaForms form data holding the reset information.
     */
    public function reset_user_password($form_data) {
        try {
            $username = $form_data['fields_by_key']['username']['value'];
            $new_password = $form_data['fields_by_key']['password']['value'];
            $new_password_confirm = $form_data['fields_by_key']['password_confirm']['value'];
            $password_reset_key = $form_data['fields_by_key']['key']['value'];
        } catch (Exception $e) {
            $username = null;
            $new_password = null;
            $new_password_confirm = null;
            $password_reset_key = null;
        }

        if ($username !== null             &&
            $new_password !== null         &&
            $new_password_confirm !== null &&
            $password_reset_key !== null      ) {
            $user_data = get_user_by('login', $username);

            global $wpdb;
            $query = $wpdb->prepare(
                'SELECT user_id FROM ' . $wpdb->prefix . 'inesonic_password_reset_key' . ' WHERE ' .
                'password_reset_key = %s',
                $password_reset_key
            );
            $query_results = $wpdb->get_results($query);

            if ($wpdb->num_rows == 1) {
                $expected_user_id = intval($query_results[0]->user_id);

                if ($user_data !== false                    &&
                    $user_data->ID == $expected_user_id     &&
                    $new_password == $new_password_confirm  &&
                    self::new_password_valid($new_password)    ) {
                    $query = $wpdb->prepare(
                        'DELETE FROM ' . $wpdb->prefix . 'inesonic_password_reset_key' . ' WHERE ' .
                            'password_reset_key = %s',
                        $password_reset_key
                    );
                    $wpdb->query($query);

                    // Note that reset_password is preferred over wp_set_password as it fires several hooks that may be
                    // used by other plug-ins.
                    reset_password($user_data, $new_password); // prefer over wp_set_password
                }
            }
        }
    }

    /**
     * Method that is triggered after a password has been reset -- Used to send a notification email to the user.
     *
     * \param[in] $user         The WP_User instance of the user that was impacted.
     *
     * \param[in] $new_password The new password.
     */
    public function report_password_reset($user, $new_password) {
        $message = $this->template_environment->render(
            $this->password_changed_template,
            array(
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'site_url' => site_url()
            )
        );

        $headers[] = 'Content-Type: text/html; charset=UTF-8';
        $success = wp_mail(
            $user->user_email,
            $this->password_changed_subject,
            $message,
            $headers
        );

        if (!$success) {
            do_action(
                'inesonic-logger-1',
                'Inesonic Password Reset Handler: Failed to send change notification to ' .
                $user_data->user_email
            );
        }

        do_action(
            'inesonic_add_history',
            $user_data->ID,
            'PASSWORD_WAS_RESET',
            ''
        );
    }

    /**
     * Method used to validate the user's password.
     *
     * \param[in] $password The password to be validated.
     *
     * \return Returns true if the password is acceptable.  Returns false if the password is not acceptable.
     */
    public static function new_password_valid($password) {
        if (strlen($password) >= 8) {
            $contains_digit = preg_match('@[0-9]@', $password);
            $contains_upper = preg_match('@[A-Z]@', $password);
            $contains_lower = preg_match('@[a-z]@', $password);
            $contains_punct = preg_match('@[^\w]@', $password);

            $is_valid = $contains_digit && $contains_upper && $contains_lower && $contains_punct;
        } else {
            $is_valid = false;
        }

        return $is_valid;
    }

    /**
     * Method that creates localized strings.
     */
    private function create_localized_strings() {
        /* The template file for password resets. */
        $this->password_reset_template = __('password_reset.html', 'inesonic-password-reset-handler');

        /* The template file for password change notifications. */
        $this->password_changed_template = __('password_changed.html', 'inesonic-password-reset-handler');

        /* Subject line for password reset */
        $this->password_reset_subject = __('Inesonic : Password Reset', 'inesonic-password-reset-handler');

        /* Subject line for password changed */
        $this->password_changed_subject = __('Inesonic : Password Changed', 'inesonic-password-reset-handler');

        /* The template file used to report that a password was reset. */
        $this->password_was_reset_template = __('password_was_reset.html', 'inesonic-password-reset-handler');
    }
}

/* Instatiate our plug-in. */
InesonicPasswordResetHandler::instance();

/* Define critical global hooks. */
register_activation_hook(__FILE__, array('InesonicPasswordResetHandler', 'plugin_activated'));
register_uninstall_hook(__FILE__, array('InesonicPasswordResetHandler', 'plugin_uninstalled'));
