<?php
/**
 * Plugin Name: wp-melli
 * Description: در شرایط قطعی اینترنت یا نیاز به قطع کردن درخواست ها به وبسایت های خاص، بهترین گزینه شما افزونه wp-melli هست
 * Version: 2.01
 * Plugin URI: https://webinew.com
 * Author: Ehsan Ghasimi | Webinew
 * Author URI: https://linkedin.com/in/ehsanghasimi
 * Text Domain: wp-melli
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.9
 * Requires PHP: 7.4
 * Update URI: https://github.com/EhsanGhasimi/wp-melli
 */

defined( 'ABSPATH' ) || exit;

/*
این افزونه توسط تیم وبینیو و احسان قسیمی بصورت اختصاصی باتوجه به شرایط اینترنت طراحی شده
به هیچ عنوان کپی از این محصول چه بصورت رایگان و چه بصورت شامل هزینه نباید انجام بشه و منتشر بشه

اختصاصی  بودن این افزونه به معنای کپی آزاد نیست!

فقط با اسم وردپرس ملی بصورت اختصاصی از سایت وبینیو قابل دریافت هست
*/


if ( ! class_exists( 'WP_Melli_HTTP_Control' ) ) {

	final class WP_Melli_HTTP_Control {

		const OPTION_KEY = 'WP_Melli_http_control_settings';
		const LOG_KEY    = 'WP_Melli_http_logs';
		const PREPARED_ASSETS_VERSION_OPTION = 'WP_Melli_prepared_assets_version';
		const PLUGIN_VERSION = '2.01';
		const DISCOVERED_ASSETS_OPTION = 'WP_Melli_discovered_external_assets';
		const CUSTOM_MAPPINGS_OPTION   = 'WP_Melli_custom_asset_mappings';

		public function __construct() {
			$settings = $this->get_settings();
			$this->maybe_prepare_local_assets();

			add_filter( 'pre_http_request', [ $this, 'filter_http_requests' ], 10, 3 );
			add_filter( 'http_request_args', [ $this, 'enforce_request_timeout' ], 20, 2 );

			add_action( 'admin_menu', [ $this, 'add_settings_page' ] );
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [ $this, 'plugin_action_links' ] );
			add_action( 'admin_init', [ $this, 'register_settings' ] );
			add_action( 'admin_init', [ $this, 'handle_clear_logs' ] );
			add_action( 'admin_init', [ $this, 'handle_asset_manager_actions' ] );
			add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
			add_action( 'wp_enqueue_scripts', [ $this, 'maybe_enqueue_vazirmatn_front' ], 20 );
			add_filter( 'script_loader_src', [ $this, 'maybe_replace_script_src' ], 20, 2 );
			add_filter( 'style_loader_src', [ $this, 'maybe_replace_style_src' ], 20, 2 );

			if ( $settings['disable_gravatar'] === 'yes' ) {
				add_filter( 'get_avatar', [ $this, 'disable_gravatar' ], 10, 5 );
			}

			if ( $settings['disable_telemetry'] === 'yes' ) {
				$this->disable_wordpress_telemetry();
			}

			if ( $settings['disable_updates'] === 'yes' ) {
				$this->disable_updates( $settings );
			}
			// اضافه کردن سیستم بافر خروجی برای فایل‌های هاردکد شده (مختص فرانت‌اند)
			if ( ! is_admin() ) {
				add_action( 'template_redirect', [ $this, 'start_output_buffer' ], 1 );
			}

			// فعال‌سازی سیستم به‌روزرسانی خودکار مستقیم از گیت‌هاب
			$this->init_github_updater();
		}

		private function maybe_prepare_local_assets() {
			$prepared_version = (string) get_option( self::PREPARED_ASSETS_VERSION_OPTION, '' );
			if ( self::PLUGIN_VERSION === $prepared_version ) {
				return;
			}

			$this->prepare_local_assets();
			update_option( self::PREPARED_ASSETS_VERSION_OPTION, self::PLUGIN_VERSION );
		}
		
		public function filter_http_requests( $preempt, $parsed_args, $url ) {
			$settings = $this->get_settings();
			$mode     = $settings['mode'];

			$host = (string) wp_parse_url( $url, PHP_URL_HOST );

			if ( ! $host ) {
				return $preempt;
			}

			$host = strtolower( $host );

			if ( $this->should_block_non_whitelisted_update_request( $url, $host, $parsed_args, $settings ) ) {
				$this->log_request( $url, $host, 'blocked_non_whitelisted_update_server' );
				return new WP_Error( 'WP_Melli_blocked', 'Blocked by WP_Melli Whitelisted Update Rule' );
			}

			if ( $mode === 'disabled' ) {
				return $preempt;
			}

			if ( 'yes' === $settings['block_mixpanel'] && $this->is_mixpanel_host( $host ) ) {
				$this->log_request( $url, $host, 'blocked_mixpanel' );
				return new WP_Error( 'WP_Melli_blocked', 'Blocked by WP_Melli Mixpanel Rule' );
			}

			if ( $mode === 'whitelist' ) {

				if ( $this->is_local_host( $host ) ) {
					return $preempt;
				}

				// استثنا برای دریافت خودکار آپدیت افزونه از گیت‌هاب رسمی
				if ( in_array( $host, [ 'api.github.com', 'github.com', 'codeload.github.com', 'objects.githubusercontent.com' ], true ) && false !== strpos( $url, 'EhsanGhasimi/wp-melli' ) ) {
					return $preempt;
				}

				$whitelist = array_map( 'trim', explode( "\n", $settings['whitelist'] ) );
				if ( ! $this->host_in_list( $host, $whitelist ) ) {
					$this->log_request( $url, $host, 'blocked_by_whitelist_mode' );
					return new WP_Error( 'WP_Melli_blocked', 'Blocked by WP_Melli Whitelist Mode' );
				}
			} elseif ( $mode === 'blacklist' ) {
				$blacklist = array_map( 'trim', explode( "\n", $settings['blacklist'] ) );
				if ( $this->host_in_list( $host, $blacklist ) ) {
					$this->log_request( $url, $host, 'blocked_by_blacklist_mode' );
					return new WP_Error( 'WP_Melli_blocked', 'Blocked by WP_Melli Blacklist Mode' );
				}
			}

			return $preempt;
		}

		public function enforce_request_timeout( $args, $url ) {
			$settings = $this->get_settings();

			if ( 'yes' !== $settings['enable_timeout_guard'] ) {
				return $args;
			}

			$timeout_limit = $this->normalize_timeout_limit( $settings['max_request_timeout'] ?? '3' );
			if ( $timeout_limit <= 0 ) {
				return $args;
			}

			$host = (string) wp_parse_url( $url, PHP_URL_HOST );
			if ( '' !== $host && $this->is_local_host( $host ) ) {
				return $args;
			}

			$current_timeout = isset( $args['timeout'] ) ? (float) $args['timeout'] : 0;
			if ( $current_timeout > 0 && $current_timeout <= $timeout_limit ) {
				return $args;
			}

			$args['timeout'] = $timeout_limit;

			if ( '' !== $host ) {
				$this->log_request( $url, strtolower( $host ), 'timeout_limited_' . (string) $timeout_limit . 's' );
			}

			return $args;
		}

		private function normalize_timeout_limit( $raw_timeout ) {
			$timeout = (int) $raw_timeout;

			if ( $timeout < 1 ) {
				return 1;
			}

			if ( $timeout > 30 ) {
				return 30;
			}

			return $timeout;
		}

		private function normalize_log_limit( $raw_limit ) {
			$limit = (int) $raw_limit;

			if ( $limit < 50 ) {
				return 50;
			}

			if ( $limit > 2000 ) {
				return 2000;
			}

			return $limit;
		}

		private function is_local_host( $host ) {
			$host = strtolower( trim( (string) $host ) );
			if ( '' === $host ) {
				return true;
			}

			if ( in_array( $host, [ 'localhost', '127.0.0.1', '::1' ], true ) ) {
				return true;
			}

			$site_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
			$site_host = strtolower( trim( $site_host ) );

			return '' !== $site_host && $host === $site_host;
		}

		private function log_request( $url, $host, $mode ) {
			$settings = $this->get_settings();
			
			if ( $settings['enable_logging'] !== 'yes' ) {
				return;
			}

			$mode = sanitize_key( (string) $mode );
			if ( '' === $mode ) {
				return;
			}

			if ( $this->is_asset_rewrite_log_mode( $mode ) && ( $settings['log_asset_events'] ?? 'no' ) !== 'yes' ) {
				return;
			}

			$host = $this->normalize_host( sanitize_text_field( (string) $host ) );
			$url  = $this->sanitize_log_url( $url );

			$logs = get_option( self::LOG_KEY, [] );
			if ( ! is_array( $logs ) ) {
				$logs = [];
			}

			$current_time = current_time( 'timestamp' );
			$retention_days = intval( $settings['log_retention_days'] ) ?: 7;
			$retention_seconds = $retention_days * DAY_IN_SECONDS;

			if ( ! empty( $logs ) ) {
				$logs = array_filter( $logs, function( $log ) use ( $current_time, $retention_seconds ) {
					if ( ! is_array( $log ) || empty( $log['time'] ) ) {
						return false;
					}

					$log_time = strtotime( (string) $log['time'] );
					if ( false === $log_time ) {
						return false;
					}

					return ( $current_time - $log_time ) <= $retention_seconds;
				});
			}

			$last_log = end( $logs );
			if ( is_array( $last_log ) ) {
				$last_time = isset( $last_log['time'] ) ? strtotime( (string) $last_log['time'] ) : false;
				$is_recent_duplicate = (
					isset( $last_log['host'], $last_log['url'], $last_log['mode'] ) &&
					$last_log['host'] === $host &&
					$last_log['url'] === $url &&
					$last_log['mode'] === $mode &&
					false !== $last_time &&
					( $current_time - $last_time ) <= MINUTE_IN_SECONDS
				);

				if ( $is_recent_duplicate ) {
					return;
				}
			}

			$logs[] = [
				'time' => current_time( 'mysql' ),
				'host' => $host,
				'url'  => $url,
				'mode' => $mode
			];

			$max_entries = isset( $settings['log_max_entries'] ) ? $this->normalize_log_limit( $settings['log_max_entries'] ) : 300;
			if ( count( $logs ) > $max_entries ) {
				$logs = array_slice( $logs, -$max_entries );
			}

			$logs = array_values( $logs );

			update_option( self::LOG_KEY, $logs, 'no' );
		}

		private function sanitize_log_url( $url ) {
			$url = trim( (string) $url );
			if ( '' === $url ) {
				return '';
			}

			$parts = wp_parse_url( $url );
			if ( ! is_array( $parts ) ) {
				return substr( sanitize_text_field( $url ), 0, 512 );
			}

			$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) . '://' : '';
			$host   = isset( $parts['host'] ) ? strtolower( (string) $parts['host'] ) : '';
			$port   = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
			$path   = isset( $parts['path'] ) ? (string) $parts['path'] : '';

			$clean_url = $scheme . $host . $port . $path;

			return substr( sanitize_text_field( $clean_url ), 0, 512 );
		}

		private function is_asset_rewrite_log_mode( $mode ) {
			return false !== strpos( (string) $mode, 'rewritten_to_local' ) || false !== strpos( (string) $mode, 'local_asset_bypassed' );
		}

		public function handle_clear_logs() {
			if ( isset( $_GET['page'] ) && $_GET['page'] === 'WP_Melli' && isset( $_GET['clear_logs'] ) && current_user_can( 'manage_options' ) ) {
				check_admin_referer( 'WP_Melli_clear_logs' );
				delete_option( self::LOG_KEY );
				wp_safe_redirect( admin_url( 'options-general.php?page=WP_Melli&logs_cleared=true' ) );
				exit;
			}
		}

		private function disable_wordpress_telemetry() {
			add_filter( 'pre_http_request', [ $this, 'block_wordpress_telemetry_request' ], 20, 3 );
		}

		public function block_wordpress_telemetry_request( $pre, $args, $url ) {
			if ( strpos( $url, 'wordpress.org' ) !== false ) {
				$host = (string) wp_parse_url( $url, PHP_URL_HOST );
				$this->log_request( $url, $host ?: 'wordpress.org', 'blocked_telemetry' );
				return new WP_Error( 'WP_Melli_blocked', 'Telemetry blocked by WP_Melli' );
			}
			return $pre;
		}

		private function disable_updates( $settings ) {
			$allow_whitelisted_updates = isset( $settings['allow_whitelisted_updates'] ) && 'yes' === $settings['allow_whitelisted_updates'];

			add_filter( 'pre_site_transient_update_core', '__return_null' );
			remove_action( 'admin_init', 'wp_version_check' );

			if ( ! $allow_whitelisted_updates ) {
				add_filter( 'pre_site_transient_update_plugins', '__return_null' );
				add_filter( 'pre_site_transient_update_themes', '__return_null' );
				remove_action( 'admin_init', 'wp_update_plugins' );
				remove_action( 'admin_init', 'wp_update_themes' );
			}
		}

		private function should_block_non_whitelisted_update_request( $url, $host, $parsed_args, $settings ) {
			if ( 'yes' !== ( $settings['disable_updates'] ?? 'no' ) ) {
				return false;
			}

			if ( 'yes' !== ( $settings['allow_whitelisted_updates'] ?? 'yes' ) ) {
				return false;
			}

			if ( ! $this->is_plugin_or_theme_update_request( $url, $parsed_args ) ) {
				return false;
			}

			if ( $this->is_local_host( $host ) ) {
				return false;
			}

			$whitelist = array_map( 'trim', explode( "\n", (string) ( $settings['whitelist'] ?? '' ) ) );

			return ! $this->host_in_list( $host, $whitelist );
		}

		private function is_plugin_or_theme_update_request( $url, $parsed_args ) {
			if ( ! is_array( $parsed_args ) ) {
				return false;
			}

			$body = isset( $parsed_args['body'] ) && is_array( $parsed_args['body'] ) ? $parsed_args['body'] : [];
			if ( isset( $body['plugins'] ) || isset( $body['themes'] ) ) {
				return true;
			}

			$path = (string) wp_parse_url( $url, PHP_URL_PATH );
			if ( '' === $path ) {
				return false;
			}

			return false !== strpos( $path, '/plugins/update-check/' ) || false !== strpos( $path, '/themes/update-check/' );
		}

		public function disable_gravatar( $avatar, $id_or_email, $size, $default, $alt ) {
			$settings = $this->get_settings();
			$custom_default = ! empty( $settings['gravatar_url'] ) ? $settings['gravatar_url'] : ( plugin_dir_url( __FILE__ ) . 'user.jpg' );

			return sprintf(
				'<img alt="%s" src="%s" class="avatar avatar-%d photo" height="%d" width="%d" />',
				esc_attr( $alt ),
				esc_url( $custom_default ),
				(int) $size,
				(int) $size,
				(int) $size
			);
		}
		
		public function register_dashboard_widget() {
			add_meta_box(
				'WP_Melli_dashboard_widget',
				'وردپرس ملی',
				[ $this, 'render_dashboard_widget' ],
				'dashboard',
				'normal',
				'high'
			);
		}

		public function render_dashboard_widget() {
			$settings_url = admin_url( 'options-general.php?page=WP_Melli' );

			echo '<div class="WP_Melli-widget-content" style="border:1px solid #d6deeb; border-radius:16px; padding:14px;">';
			echo '<div style="display:flex; align-items:center; gap:12px; margin-bottom:10px; background:#051b41; border-radius:12px; padding:10px 12px;">';
			echo '<div style="width:40px; height:40px; border-radius:10px; background:rgba(252, 203, 4, 0.16); display:flex; align-items:center; justify-content:center;">';
			echo '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 18l.01 0" /><path d="M9.172 15.172a4 4 0 0 1 5.656 0" /><path d="M6.343 12.343a7.963 7.963 0 0 1 3.864 -2.14m4.163 .155a7.965 7.965 0 0 1 3.287 2" /><path d="M3.515 9.515a12 12 0 0 1 3.544 -2.455m3.101 -.92a12 12 0 0 1 10.325 3.374" /><path d="M3 3l18 18" /></svg>';
			echo '</div>';
			echo '<div>';
			echo '<strong style="display:block; color:#ffffff;">افزونه wp-melli</strong>';
echo '<small style="color:#fccb04;">توسعه یافته توسط وبینیو</small>';
			echo '</div>';
			echo '</div>';
			echo '<p><strong>همه درخواست ها رو مدیریت کنید تا در شرایط قطع بودن دسترسی سرور شما به اینترنت جهانی بتوانید بدون کاهش سرعت از سایت وردپرس خودتون استفاده کنید.</strong></p>';
			echo '<p><strong>برای دریافت تغییرات و اطلاعات مهم حتما سایت و کانال پیامرسان داخلی را داشته باشید</strong></p>';
			echo '<ul>';
echo '<li><a href="https://webinew.com" target="_blank" rel="noopener noreferrer">سایت وبینیو</a></li>';
echo '<li><a href="https://ble.ir/join/E6mHR6mviv" target="_blank" rel="noopener noreferrer">کانال بله وبینیو</a></li>';
echo '<li><a href="https://wa.me/989159677791" target="_blank" rel="noopener noreferrer">پشتیبانی واتس‌اپ (09159677791)</a></li>';
echo '</ul>';
			echo '<p><a class="button button-primary" href="' . esc_url( $settings_url ) . '">تنظیمات افزونه</a></p>';
			echo '</div>';
		}

		public function add_settings_page() {
			add_options_page(
				'تنظیمات وردپرس ملی',
				'وردپرس ملی',
				'manage_options',
				'WP_Melli',
				[ $this, 'render_settings_page' ]
			);
		}

		public function plugin_action_links( $links ) {
			$settings_url = admin_url( 'options-general.php?page=WP_Melli' );
			$custom_links = [
    '<a href="' . esc_url( $settings_url ) . '">تنظیمات</a>',
    '<a href="https://webinew.com" target="_blank" rel="noopener noreferrer">سایت توسعه دهنده</a>',
];

			return array_merge( $custom_links, $links );
		}


		public function register_settings() {
			register_setting(
				'WP_Melli_group',
				self::OPTION_KEY,
				[ 'sanitize_callback' => [ $this, 'sanitize_settings' ] ]
			);
		}

		public function sanitize_settings( $input ) {
			$input = is_array( $input ) ? $input : [];

			$mode = isset( $input['mode'] ) ? sanitize_text_field( $input['mode'] ) : 'disabled';
			if ( ! in_array( $mode, [ 'disabled', 'whitelist', 'blacklist' ], true ) ) {
				$mode = 'disabled';
			}

			$gravatar_url = isset( $input['gravatar_url'] ) ? esc_url_raw( trim( (string) $input['gravatar_url'] ) ) : '';
			if ( '' === $gravatar_url ) {
				$gravatar_url = plugin_dir_url( __FILE__ ) . 'user.jpg';
			}

			$retention_days = isset( $input['log_retention_days'] ) ? (string) intval( $input['log_retention_days'] ) : '7';
			if ( ! in_array( $retention_days, [ '1', '3', '7', '15', '30' ], true ) ) {
				$retention_days = '7';
			}
			$log_max_entries = isset( $input['log_max_entries'] ) ? (string) $this->normalize_log_limit( $input['log_max_entries'] ) : '300';

			$max_request_timeout = isset( $input['max_request_timeout'] ) ? (string) $this->normalize_timeout_limit( $input['max_request_timeout'] ) : '3';

			return [
				'mode'                => $mode,
				'whitelist'           => $this->sanitize_host_list( $input['whitelist'] ?? '' ),
				'blacklist'           => $this->sanitize_host_list( $input['blacklist'] ?? '' ),
				'disable_telemetry'   => isset( $input['disable_telemetry'] ) ? 'yes' : 'no',
				'disable_updates'     => isset( $input['disable_updates'] ) ? 'yes' : 'no',
				'allow_whitelisted_updates' => isset( $input['allow_whitelisted_updates'] ) ? 'yes' : 'no',
				'disable_gravatar'    => isset( $input['disable_gravatar'] ) ? 'yes' : 'no',
				'gravatar_url'        => $gravatar_url,
				'enable_logging'      => isset( $input['enable_logging'] ) ? 'yes' : 'no',
				'log_retention_days'  => $retention_days,
				'log_max_entries'     => $log_max_entries,
				'log_asset_events'    => isset( $input['log_asset_events'] ) ? 'yes' : 'no',
				'local_asset_rewrite' => isset( $input['local_asset_rewrite'] ) ? 'yes' : 'no',
				'block_mixpanel'      => isset( $input['block_mixpanel'] ) ? 'yes' : 'no',
				'strict_asset_block'  => isset( $input['strict_asset_block'] ) ? 'yes' : 'no',
				'enable_front_vazirmatn' => isset( $input['enable_front_vazirmatn'] ) ? 'yes' : 'no',
				'enable_timeout_guard'=> isset( $input['enable_timeout_guard'] ) ? 'yes' : 'no',
				'max_request_timeout' => $max_request_timeout,
			];
		}

		private function sanitize_host_list( $raw_hosts ) {
			$raw_hosts = is_string( $raw_hosts ) ? $raw_hosts : '';
			$lines     = preg_split( '/\r\n|\r|\n/', $raw_hosts );
			$hosts     = [];

			foreach ( $lines as $line ) {
				$line = trim( $line );
				if ( '' === $line ) {
					continue;
				}

				$host = wp_parse_url( $line, PHP_URL_HOST );
				if ( ! $host ) {
					$host = $line;
				}

				$host = strtolower( trim( (string) $host ) );
				$host = preg_replace( '/:\\d+$/', '', $host );

				if ( '' !== $host ) {
					$hosts[] = $host;
				}
			}

			$hosts = array_values( array_unique( $hosts ) );

			return implode( "\n", $hosts );
		}

		private function host_in_list( $host, $domains ) {
			$host = strtolower( trim( (string) $host ) );
			if ( '' === $host || ! is_array( $domains ) ) {
				return false;
			}

			foreach ( $domains as $domain ) {
				$domain = strtolower( trim( (string) $domain ) );
				if ( '' === $domain ) {
					continue;
				}

				if ( $host === $domain ) {
					return true;
				}

				$suffix = '.' . $domain;
				if ( strlen( $host ) > strlen( $domain ) && substr( $host, -strlen( $suffix ) ) === $suffix ) {
					return true;
				}
			}

			return false;
		}

		private function get_quick_whitelist_presets() {
			$category_presets = [
				[
					'label'   => 'زیرساخت و CDN ایرانی',
					'domains' => $this->get_iranian_cdn_infra_domains(),
				],
				[
					'label'   => 'نقشه و مسیریابی',
					'domains' => $this->get_iranian_map_domains(),
				],
				[
					'label'   => 'تبلیغات و آنالیتیکس',
					'domains' => $this->get_iranian_ads_domains(),
				],
				[
					'label'   => 'هاستینگ ایرانی',
					'domains' => $this->get_iranian_hosting_domains(),
				],
				[
					'label'   => 'وبسایت های ایرانی پرکاربرد',
					'domains' => $this->get_iranian_popular_sites_domains(),
				],
				[
					'label'   => 'سرویس های دولتی و اعتماد',
					'domains' => $this->get_iranian_gov_trust_domains(),
				],
				[
					'label'   => 'فونت، ایمیل و مارکت های ایرانی',
					'domains' => $this->get_iranian_misc_domains(),
				],
				[
					'label'   => 'لایسنس افزونه و قالب ایرانی',
					'domains' => $this->get_license_vendor_domains(),
				],
				[
					'label'   => 'شرکت های PSP شاپرک',
					'domains' => $this->get_psp_domains(),
				],
				[
					'label'   => 'پرداخت یارها (درگاه ها)',
					'domains' => $this->get_paymentyar_domains(),
				],
				[
					'label'   => 'پرداخت اقساطی',
					'domains' => $this->get_installment_payment_api_domains(),
				],
				[
					'label'   => 'پیامرسان های داخلی',
					'domains' => $this->get_iranian_messenger_api_domains(),
				],
				[
					'label'   => 'پنل های پیامکی',
					'domains' => $this->get_sms_panel_api_domains(),
				],
				[
					'label'   => 'سرویس های ارسال پستی و پیک',
					'domains' => $this->get_shipping_api_domains(),
				],
			];

			$all_domains = [];
			foreach ( $category_presets as $preset ) {
				if ( ! empty( $preset['domains'] ) && is_array( $preset['domains'] ) ) {
					$all_domains = array_merge( $all_domains, $preset['domains'] );
				}
			}

			$aggregate_preset = [
				'label'   => 'همه دامنه ها اضافه شود',
				'domains' => array_values( array_unique( $all_domains ) ),
			];

			return array_merge( [ $aggregate_preset ], $category_presets );
		}

		private function get_license_vendor_domains() {
			return [
				'webinew.com',
				'api.webinew.com',
				'dl.webinew.com',
				'abzarwp.com',
				'api.abzarwp.com',
				'cdn.abzarwp.com',
				'dl.abzarwp.com',
				'zhaket.com',
				'api.zhaket.com',
				'cdn.zhaket.com',
				'files.zhaket.com',
				'rtl-theme.com',
				'api.rtl-theme.com',
				'cdn.rtl-theme.com',
				'dl.rtl-theme.com',
				'mihanwp.com',
				'elementorfa.ir',
				'api.elementorfa.ir',
				'elementor-site.ir',
				'elementor-site.ir',
				'woocommerce.ir',
			];
		}

		private function get_psp_domains() {
			return [
				'pep.co.ir',
				'sep.ir',
				'sep.shaparak.ir',
				'pna.co.ir',
				'pec.ir',
				'sadadpsp.ir',
				'omidpayment.ir',
				'fanavacard.ir',
				'sepehrpay.com',
				'irankish.com',
				'behpardakht.com',
				'ecd-co.ir',
				'asanpardakht.ir',
			];
		}

		private function get_paymentyar_domains() {
			return [
				'zarinpal.com',
				'www.zarinpal.com',
				'api.zarinpal.com',
				'payment.zarinpal.com',
				'nextpay.org',
				'api.nextpay.org',
				'idpay.ir',
				'api.idpay.ir',
				'pay.ir',
				'api.pay.ir',
				'vandar.io',
				'api.vandar.io',
				'jibit.ir',
				'api.jibit.ir',
				'zibal.ir',
				'api.zibal.ir',
				'payping.ir',
				'api.payping.ir',
			];
		}

		private function get_installment_payment_api_domains() {
			return [
				'digipay.ir',
				'api.digipay.ir',
				'mydigipay.com',
				'api.mydigipay.com',
				'azkivam.com',
				'api.azkivam.com',
				'torob.com',
				'torob.ir',
				'api.torob.ir',
				'api.torob.com',
				'torobpay.com',
				'api.torobpay.com',
				'snapppay.ir',
				'api.snapppay.ir',
				'lendo.ir',
				'api.lendo.ir',
				'tara360.com',
				'api.tara360.com',
				'api.tara360.ir',
				'tara360.ir',
			];
		}

		private function get_iranian_messenger_api_domains() {
			return [
				'bale.ai',
				'safir.bale.ai',
				'tapi.bale.ai',
				'api.bale.ai',
				'botapi.bale.ai',
				'eitaa.com',
				'api.eitaa.com',
				'rubika.ir',
				'api.rubika.ir',
				'splus.ir',
				'api.splus.ir',
				'gap.im',
				'api.gap.im',
				'igap.net',
				'api.igap.net',
				'soroush-app.ir',
				'api.soroush-app.ir',
			];
		}

		private function get_sms_panel_api_domains() {
			return [
				'kavenegar.com',
				'api.kavenegar.com',
				'avanak.ir',
				'portal.avanak.ir',
				'sms.ir',
				'api.sms.ir',
				'ghasedak.me',
				'api.ghasedak.me',
				'gateway.ghasedak.me',
				'melipayamak.com',
				'api.melipayamak.com',
				'api.payamak-panel.com',
				'rest.payamak-panel.com',
				'ippanel.com',
				'api2.ippanel.com',
				'edge.ippanel.com',
				'limosms.com',
				'api.limosms.com',
				'api.mediana.ir',
				'farazsms.com',
				'api.farazsms.com',
				'api.iranpayamak.com',
				'api.sabanovin.com',
				'api.sms-webservice.com',
				'smspanel.trez.ir',
				'magfa.com',
				'sms.magfa.com',
				'payamresan.com',
				'api.payamresan.com',
			];
		}

		private function get_shipping_api_domains() {
			return [
				'post.ir',
				'api.post.ir',
				'ecommerce.post.ir',
				'tipaxco.com',
				'api.tipaxco.com',
				'chaparnet.com',
				'api.chaparnet.com',
				'postex.ir',
				'api.postex.ir',
				'mahex.com',
				'api.mahex.com',
				'alopeyk.com',
				'api.alopeyk.com',
				'miare.co',
				'api.miare.co',
			];
		}

		private function get_iranian_cdn_infra_domains() {
			return [
				'cdn.arvancloud.ir',
				'static.arvancloud.ir',
				'arvancloud.ir',
				'arvanstorage.ir',
				'liara.run.ir',
				'liara.ir',
				'arvancloud.com',
				'cdn.arvancloud.com',
				'parspack.com',
				'cdn.parspack.com',
				'abr.ir',
			];
		}

		private function get_iranian_map_domains() {
			return [
				'neshan.org',
				'api.neshan.org',
				'cedarmaps.com',
				'api.cedarmaps.com',
				'map.ir',
				'balad.ir',
				'api.balad.ir',
			];
		}

		private function get_iranian_ads_domains() {
			return [
				'yektanet.com',
				'cdn.yektanet.com',
				'tapsell.ir',
				'adivery.ir',
				'mediaad.org',
			];
		}

		private function get_iranian_hosting_domains() {
			return [
				'mizbanfa.com',
				'hostiran.net',
				'hostiran.com',
				'netafraz.com',
				'limoo.host',
				'iran.liara.run',
				'liara.run',
				'darkube.app',
				'hamravesh.com',
				'fandogh.cloud',
				'sotoon.ir',
			];
		}

		private function get_iranian_popular_sites_domains() {
			return [
				'digikala.com',
				'api.digikala.com',
				'divar.ir',
				'api.divar.ir',
				'torob.com',
				'api.torob.com',
				'emalls.ir',
				'www.emalls.ir',
				'api.emalls.ir',
				'cdn.emalls.ir',
				'tapin.ir',
				'www.tapin.ir',
				'api.tapin.ir',
				'panel.tapin.ir',
				'cdn.tapin.ir',
				'services.tapin.ir',
				'api.basalam.com',
				'developers.basalam.com',
				'panel.basalam.com',
				'chat.basalam.com',
				'ai.basalam.com',
				'cdn.basalam.com',
				'basalam.com',
				'www.basalam.com',
				'didar.me',
				'snapp.ir',
				'tapsi.ir',
				'aparat.com',
				'filimo.com',
				'namava.ir',
				'telewebion.com',
				'rubika.ir',
				'bale.ai',
				'eitaa.com',
				'gap.im',
				'igap.net',
				'soroush-app.ir',
			];
		}

		private function get_iranian_gov_trust_domains() {
			return [
				'nic.ir',
				'irnic.ir',
				'enamad.ir',
				'samandehi.ir',
			];
		}

		private function get_iranian_misc_domains() {
			return [
				'chmail.ir',
				'parsmail.com',
				'v1.fontapi.ir',
				'fonts.irfonts.ir',
				'cdn.fontiran.com',
				'fontiran.com',
				'cafebazaar.ir',
				'myket.ir',
				'charkhoneh.com',
				'sibche.com',
				'virgool.io',
				'zoomit.ir',
			];
		}

		private function get_settings() {
			$saved = get_option( self::OPTION_KEY, [] );

			$defaults = [
				'mode'               => 'disabled',
				'whitelist'          => 'api.webinew.com',
				'blacklist'          => '',
				'disable_telemetry'  => 'yes',
				'disable_updates'    => 'yes',
				'allow_whitelisted_updates' => 'yes',
				'disable_gravatar'   => 'yes',
				'gravatar_url'       => plugin_dir_url(__FILE__) . 'user.jpg',
				'enable_logging'     => 'no',
				'log_retention_days' => '7',
				'log_max_entries'    => '300',
				'log_asset_events'   => 'no',
				'local_asset_rewrite'=> 'yes',
				'block_mixpanel'     => 'yes',
				'strict_asset_block' => 'yes',
				'enable_front_vazirmatn' => 'no',
				'enable_timeout_guard'=> 'no',
				'max_request_timeout'=> '3',
			];

			return wp_parse_args( $saved, $defaults );
		}

		private function is_customizer_context() {
			global $pagenow;

			if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {
				return true;
			}

			if ( is_admin() && 'customize.php' === $pagenow ) {
				return true;
			}

			return isset( $_REQUEST['customize_changeset_uuid'] ) || isset( $_REQUEST['customize_theme'] ) || isset( $_REQUEST['customize_messenger_channel'] );
		}

		public function maybe_replace_script_src( $src, $handle ) {
			$settings = $this->get_settings();
			if ( 'yes' !== $settings['local_asset_rewrite'] ) {
				return $src;
			}

			if ( $this->is_customizer_context() ) {
				return $src;
			}

			$host = (string) wp_parse_url( $src, PHP_URL_HOST );
			$path = (string) wp_parse_url( $src, PHP_URL_PATH );

			if ( '' === $host || '' === $path ) {
				return $src;
			}

			$host = strtolower( $host );

			if ( $this->is_same_site_host( $host ) ) {
				$this->log_request( $src, $host, 'local_asset_bypassed_same_host_script' );
				return $src;
			}

			if ( $this->is_blacklisted_asset_host( $host, $settings ) ) {
				$this->log_request( $src, $host, 'blocked_by_blacklist_asset_script' );
				return plugin_dir_url( __FILE__ ) . 'assets/js/blocked-asset.js';
			}

			if ( 'yes' === $settings['block_mixpanel'] && $this->is_mixpanel_host( $host ) ) {
				$this->log_request( $src, $host, 'mixpanel_rewritten_to_local_stub' );
				return plugin_dir_url( __FILE__ ) . 'assets/js/mixpanel-stub.js';
			}

			$this->record_discovered_asset( $src, $handle, 'script', $host, $path );

			$custom_replacement = $this->get_custom_asset_replacement( $src );
			if ( $custom_replacement ) {
				$this->log_request( $src, $host, 'custom_script_rewritten_to_local' );
				return $custom_replacement;
			}

			$replacement = $this->map_script_path_to_local( $path, $src );
			if ( $replacement ) {
				$this->log_request( $src, $host, 'cdn_rewritten_to_local' );
				return $replacement;
			}

			if ( $this->should_block_external_assets( $host, $settings ) ) {
				$this->log_request( $src, $host, 'blocked_external_script_no_local' );
				return plugin_dir_url( __FILE__ ) . 'assets/js/blocked-asset.js';
			}

			return $src;
		}

		public function maybe_replace_style_src( $src, $handle ) {
			$settings = $this->get_settings();
			if ( 'yes' !== $settings['local_asset_rewrite'] ) {
				return $src;
			}

			if ( $this->is_customizer_context() ) {
				return $src;
			}

			$host = (string) wp_parse_url( $src, PHP_URL_HOST );
			$path = (string) wp_parse_url( $src, PHP_URL_PATH );

			if ( '' === $host || '' === $path ) {
				return $src;
			}

			$host = strtolower( $host );
			$path = strtolower( $path );

			if ( $this->is_same_site_host( $host ) ) {
				$this->log_request( $src, $host, 'local_asset_bypassed_same_host_style' );
				return $src;
			}

			if ( $this->is_blacklisted_asset_host( $host, $settings ) ) {
				$this->log_request( $src, $host, 'blocked_by_blacklist_asset_style' );
				return plugin_dir_url( __FILE__ ) . 'assets/css/blocked-asset.css';
			}

			$this->record_discovered_asset( $src, $handle, 'style', $host, $path );

			$custom_replacement = $this->get_custom_asset_replacement( $src );
			if ( $custom_replacement ) {
				$this->log_request( $src, $host, 'custom_style_rewritten_to_local' );
				return $custom_replacement;
			}

			$replacement = $this->map_style_path_to_local( $path, $src, $host );
			if ( $replacement ) {
				return $replacement;
			}

			if ( $this->should_block_external_assets( $host, $settings ) ) {
				$this->log_request( $src, $host, 'blocked_external_style_no_local' );
				return plugin_dir_url( __FILE__ ) . 'assets/css/blocked-asset.css';
			}

			return $src;
		}

		public function maybe_enqueue_vazirmatn_front() {
			if ( is_admin() ) {
				return;
			}

			$settings = $this->get_settings();
			if ( 'yes' !== ( $settings['enable_front_vazirmatn'] ?? 'no' ) ) {
				return;
			}

			$vazirmatn_css_path = plugin_dir_path( __FILE__ ) . 'assets/vendor/google-fonts/vazirmatn.css';
			if ( ! file_exists( $vazirmatn_css_path ) ) {
				return;
			}

			wp_enqueue_style(
				'WP_Melli-vazirmatn',
				plugin_dir_url( __FILE__ ) . 'assets/vendor/google-fonts/vazirmatn.css',
				[],
				'1.0.0'
			);
		}

		private function map_style_path_to_local( $path, $original_src, $host ) {
			$fontawesome_base_url = plugin_dir_url( __FILE__ ) . 'assets/vendor/fontawesome/css/';
			$fontawesome_base_dir = plugin_dir_path( __FILE__ ) . 'assets/vendor/fontawesome/css/';

			if ( strpos( $path, 'fontawesome-free' ) !== false && strpos( $path, '/all.min.css' ) !== false && file_exists( $fontawesome_base_dir . 'all.min.css' ) ) {
				$this->log_request( $original_src, $host, 'fontawesome_all_rewritten_to_local' );
				return $fontawesome_base_url . 'all.min.css';
			}

			if ( strpos( $path, 'fontawesome-free' ) !== false && strpos( $path, '/v4-shims.min.css' ) !== false && file_exists( $fontawesome_base_dir . 'v4-shims.min.css' ) ) {
				$this->log_request( $original_src, $host, 'fontawesome_shims_rewritten_to_local' );
				return $fontawesome_base_url . 'v4-shims.min.css';
			}

			if ( 'fonts.googleapis.com' === $host && 0 === strpos( $path, '/css' ) ) {
				$families = $this->extract_google_font_families( $original_src );

				if ( in_array( 'vazirmatn', $families, true ) ) {
					$vazirmatn_css = plugin_dir_path( __FILE__ ) . 'assets/vendor/google-fonts/vazirmatn.css';
					if ( file_exists( $vazirmatn_css ) ) {
						$this->log_request( $original_src, $host, 'google_fonts_vazirmatn_rewritten_to_local' );
						return plugin_dir_url( __FILE__ ) . 'assets/vendor/google-fonts/vazirmatn.css';
					}
				}

				if ( in_array( 'roboto', $families, true ) || empty( $families ) ) {
					$roboto_css = plugin_dir_path( __FILE__ ) . 'assets/vendor/google-fonts/roboto.css';
					if ( file_exists( $roboto_css ) ) {
						$this->log_request( $original_src, $host, 'google_fonts_rewritten_to_local' );
						return plugin_dir_url( __FILE__ ) . 'assets/vendor/google-fonts/roboto.css';
					}
				}
			}

			$swiper_css_path = plugin_dir_path( __FILE__ ) . 'assets/vendor/swiper/swiper-bundle.min.css';
			if ( preg_match( '#/swiper(-bundle)?(\\.min)?\\.css$#', $path ) && file_exists( $swiper_css_path ) ) {
				$this->log_request( $original_src, $host, 'swiper_rewritten_to_local' );
				return plugin_dir_url( __FILE__ ) . 'assets/vendor/swiper/swiper-bundle.min.css';
			}

			if ( strpos( $path, 'dashicons' ) !== false ) {
				$this->log_request( $original_src, $host, 'dashicons_rewritten_to_local' );
				return plugin_dir_url( __FILE__ ) . 'assets/vendor/dashicons/css/dashicons.min.css';
			}

			if ( strpos( $path, 'eicons' ) !== false || strpos( $path, 'elementor-icons' ) !== false ) {
				$this->log_request( $original_src, $host, 'eicons_rewritten_to_local' );
				return plugin_dir_url( __FILE__ ) . 'assets/vendor/eicons/css/elementor-icons.min.css';
			}

			return '';
		}

		private function extract_google_font_families( $src ) {
			$query = (string) wp_parse_url( $src, PHP_URL_QUERY );
			if ( '' === $query ) {
				return [];
			}

			$families = [];
			$pairs    = explode( '&', $query );

			foreach ( $pairs as $pair ) {
				$pair = trim( (string) $pair );
				if ( '' === $pair ) {
					continue;
				}

				$key_value = explode( '=', $pair, 2 );
				$key       = isset( $key_value[0] ) ? urldecode( (string) $key_value[0] ) : '';
				$value     = isset( $key_value[1] ) ? urldecode( (string) $key_value[1] ) : '';

				if ( 'family' !== strtolower( $key ) || '' === $value ) {
					continue;
				}

				$family_parts = explode( '|', $value );
				foreach ( $family_parts as $family_part ) {
					$family_part = trim( (string) $family_part );
					if ( '' === $family_part ) {
						continue;
					}

					$family_name = explode( ':', $family_part, 2 )[0];
					$family_name = strtolower( trim( str_replace( '+', ' ', $family_name ) ) );
					if ( '' !== $family_name ) {
						$families[] = $family_name;
					}
				}
			}

			return array_values( array_unique( $families ) );
		}

		private function should_block_external_assets( $host, $settings ) {
			if ( 'yes' !== $settings['strict_asset_block'] ) {
				return false;
			}

			if ( ! $this->is_known_cdn_host( $host ) && ! $this->is_mixpanel_host( $host ) ) {
				return false;
			}

			if ( isset( $settings['mode'] ) && 'whitelist' === $settings['mode'] ) {
				$whitelist = array_map( 'trim', explode( "\n", (string) ( $settings['whitelist'] ?? '' ) ) );
				if ( $this->host_in_list( $host, $whitelist ) ) {
					return false;
				}
			}

			$site_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
			$site_host = strtolower( $site_host );

			if ( '' === $site_host ) {
				return $this->is_known_cdn_host( $host );
			}

			return $host !== $site_host;
		}

		private function is_blacklisted_asset_host( $host, $settings ) {
			if ( ! is_array( $settings ) || ! isset( $settings['mode'] ) || 'blacklist' !== $settings['mode'] ) {
				return false;
			}

			$blacklist = array_map( 'trim', explode( "\n", (string) ( $settings['blacklist'] ?? '' ) ) );

			return $this->host_in_list( $host, $blacklist );
		}

		private function is_same_site_host( $host ) {
			$site_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
			if ( '' === $site_host || '' === $host ) {
				return false;
			}

			return $this->normalize_host( $site_host ) === $this->normalize_host( $host );
		}

		private function normalize_host( $host ) {
			$host = strtolower( trim( (string) $host ) );
			if ( 0 === strpos( $host, 'www.' ) ) {
				$host = substr( $host, 4 );
			}

			return $host;
		}

		private function is_known_cdn_host( $host ) {
			$cdn_hosts = [
				'ajax.googleapis.com',
				'cdnjs.cloudflare.com',
				'cdn.jsdelivr.net',
				'unpkg.com',
				'code.jquery.com',
				'fonts.googleapis.com',
				'fonts.gstatic.com',
				'use.fontawesome.com',
				'kit.fontawesome.com',
				'maxcdn.bootstrapcdn.com',
			];

			return in_array( $host, $cdn_hosts, true );
		}

		private function map_script_path_to_local( $path, $original_src ) {
			$path = strtolower( $path );
			$plugin_url = plugin_dir_url( __FILE__ ) . 'assets/vendor/wp-core-js/';
			$swiper_path = plugin_dir_path( __FILE__ ) . 'assets/vendor/swiper/swiper-bundle.min.js';
			$ace_base_dir = plugin_dir_path( __FILE__ ) . 'assets/vendor/ace-builds/src-min-noconflict/';
			$ace_base_url = plugin_dir_url( __FILE__ ) . 'assets/vendor/ace-builds/src-min-noconflict/';

			if ( preg_match( '#/ace(-min)?\\.js$#', $path ) && file_exists( $ace_base_dir . 'ace.min.js' ) ) {
				return $ace_base_url . 'ace.min.js';
			}

			if ( preg_match( '#/ext-language_tools\\.js$#', $path ) && file_exists( $ace_base_dir . 'ext-language_tools.js' ) ) {
				return $ace_base_url . 'ext-language_tools.js';
			}

			if ( preg_match( '#/swiper(-bundle)?(\\.min)?\\.js$#', $path ) && file_exists( $swiper_path ) ) {
				return plugin_dir_url( __FILE__ ) . 'assets/vendor/swiper/swiper-bundle.min.js';
			}

			if ( preg_match( '#/jquery(\\.min)?\\.js$#', $path ) ) {
				return $plugin_url . 'jquery.min.js';
			}

			if ( preg_match( '#/jquery-migrate(\\.min)?\\.js$#', $path ) ) {
				return $plugin_url . 'jquery-migrate.min.js';
			}

			if ( preg_match( '#/underscore(-min)?\\.js$#', $path ) ) {
				return $plugin_url . 'underscore.min.js';
			}

			if ( preg_match( '#/backbone(-min)?\\.js$#', $path ) ) {
				return $plugin_url . 'backbone.min.js';
			}

			if ( preg_match( '#/react(\\.production\\.min|\\.min)?\\.js$#', $path ) ) {
				return $plugin_url . 'react.min.js';
			}

			if ( preg_match( '#/react-dom(\\.production\\.min|\\.min)?\\.js$#', $path ) ) {
				return $plugin_url . 'react-dom.min.js';
			}

			return apply_filters( 'WP_Melli_local_script_rewrite', '', $path, $original_src );
		}

		private function is_mixpanel_host( $host ) {
			$mixpanel_hosts = [
				'api-eu.mixpanel.com',
				'api.mixpanel.com',
				'cdn.mxpnl.com',
				'api-js.mixpanel.com',
			];

			return in_array( $host, $mixpanel_hosts, true );
		}

		private function prepare_local_assets() {
			$this->ensure_core_js_assets();
			$this->ensure_ace_assets();
			$this->ensure_dashicons_assets();
			$this->ensure_eicons_assets();
			$this->ensure_swiper_assets();
			$this->ensure_fontawesome_assets();
			$this->ensure_google_fonts_assets();
			$this->ensure_block_fallback_assets();
		}

		private function ensure_ace_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$this->ensure_dir( $plugin_base . 'assets/vendor/ace-builds/src-min-noconflict/' );
		}

		private function ensure_block_fallback_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$this->ensure_dir( $plugin_base . 'assets/js/' );
			$this->ensure_dir( $plugin_base . 'assets/css/' );

			$blocked_js = $plugin_base . 'assets/js/blocked-asset.js';
			if ( ! file_exists( $blocked_js ) ) {
				file_put_contents( $blocked_js, "/* blocked external script by WP_Melli */\n" );
			}

			$blocked_css = $plugin_base . 'assets/css/blocked-asset.css';
			if ( ! file_exists( $blocked_css ) ) {
				file_put_contents( $blocked_css, "/* blocked external style by WP_Melli */\n" );
			}
		}

		private function ensure_fontawesome_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$target_css_dir = $plugin_base . 'assets/vendor/fontawesome/css/';
			$target_webfonts_dir = $plugin_base . 'assets/vendor/fontawesome/webfonts/';

			$this->ensure_dir( $target_css_dir );
			$this->ensure_dir( $target_webfonts_dir );
		}

		private function ensure_google_fonts_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$this->ensure_dir( $plugin_base . 'assets/vendor/google-fonts/' );
			$this->ensure_dir( $plugin_base . 'assets/vendor/google-fonts/fonts/' );
			$this->ensure_vazirmatn_assets();
		}

		private function ensure_vazirmatn_assets() {
			$plugin_base      = plugin_dir_path( __FILE__ );
			$target_base_dir  = $plugin_base . 'assets/vendor/google-fonts/fonts/vazirmatn/';
			$target_css       = $plugin_base . 'assets/vendor/google-fonts/vazirmatn.css';
			$font_file_weights = [
				'Vazirmatn-Regular.woff2' => '400',
				'Vazirmatn-Medium.woff2'  => '500',
				'Vazirmatn-Bold.woff2'    => '700',
			];

			$this->ensure_dir( $target_base_dir );

			foreach ( $font_file_weights as $font_file => $weight ) {
				$target_file = $target_base_dir . $font_file;
				if ( file_exists( $target_file ) ) {
					continue;
				}

				$source_file = $this->find_vazirmatn_source_font( $font_file );
				if ( '' !== $source_file ) {
					@copy( $source_file, $target_file );
				}
			}

			$css_lines = [ "/* WP_Melli local Vazirmatn */" ];
			$added_face = false;

			foreach ( $font_file_weights as $font_file => $weight ) {
				$target_file = $target_base_dir . $font_file;
				if ( ! file_exists( $target_file ) ) {
					continue;
				}

				$added_face = true;
				$css_lines[] = "@font-face{font-family:'Vazirmatn';font-style:normal;font-weight:" . $weight . ";font-display:swap;src:url('fonts/vazirmatn/" . $font_file . "') format('woff2');}";
			}

			if ( ! $added_face ) {
				$css_lines[] = "@font-face{font-family:'Vazirmatn';font-style:normal;font-weight:400;font-display:swap;src:local('Vazirmatn');}";
			}

			$css_lines[] = ".WP_Melli-font-vazirmatn{font-family:'Vazirmatn',sans-serif;}";
			$css_content = implode( "\n", $css_lines ) . "\n";
			$current_css = file_exists( $target_css ) ? (string) file_get_contents( $target_css ) : '';

			if ( $current_css !== $css_content ) {
				file_put_contents( $target_css, $css_content );
			}
		}

		private function find_vazirmatn_source_font( $font_file ) {
			$font_file = trim( (string) $font_file );
			if ( '' === $font_file ) {
				return '';
			}

			$glob_patterns = [
				WP_CONTENT_DIR . '/plugins/*/assets/fonts/vazirmatn/' . $font_file,
				WP_CONTENT_DIR . '/themes/*/assets/fonts/vazirmatn/' . $font_file,
				WP_CONTENT_DIR . '/themes/*/fonts/vazirmatn/' . $font_file,
			];

			foreach ( $glob_patterns as $glob_pattern ) {
				$matches = glob( $glob_pattern );
				if ( ! is_array( $matches ) || empty( $matches ) ) {
					continue;
				}

				foreach ( $matches as $match ) {
					if ( is_file( $match ) ) {
						return $match;
					}
				}
			}

			return '';
		}

		private function ensure_swiper_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$target_dir  = $plugin_base . 'assets/vendor/swiper/';
			$target_js   = $target_dir . 'swiper-bundle.min.js';
			$target_css  = $target_dir . 'swiper-bundle.min.css';

			if ( file_exists( $target_js ) && file_exists( $target_css ) ) {
				return;
			}

			$this->ensure_dir( $target_dir );

			$source_js = $this->find_first_existing_file(
				[
					WP_CONTENT_DIR . '/plugins/elementor/assets/lib/swiper/v8/swiper.min.js',
					WP_CONTENT_DIR . '/plugins/elementor/assets/lib/swiper/swiper.min.js',
					ABSPATH . 'wp-includes/js/dist/vendor/swiper/swiper-bundle.min.js',
				]
			);

			$source_css = $this->find_first_existing_file(
				[
					WP_CONTENT_DIR . '/plugins/elementor/assets/lib/swiper/v8/css/swiper.min.css',
					WP_CONTENT_DIR . '/plugins/elementor/assets/lib/swiper/swiper.min.css',
					ABSPATH . 'wp-includes/css/dist/vendor/swiper/swiper-bundle.min.css',
				]
			);

			if ( $source_js && ! file_exists( $target_js ) ) {
				@copy( $source_js, $target_js );
			}

			if ( $source_css && ! file_exists( $target_css ) ) {
				@copy( $source_css, $target_css );
			}
		}

		private function find_first_existing_file( $candidates ) {
			foreach ( $candidates as $candidate ) {
				if ( is_file( $candidate ) ) {
					return $candidate;
				}
			}

			return '';
		}

		private function ensure_core_js_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$target_base = $plugin_base . 'assets/vendor/wp-core-js/';

			$asset_map = [
				'jquery.min.js'         => ABSPATH . 'wp-includes/js/jquery/jquery.min.js',
				'jquery-migrate.min.js' => ABSPATH . 'wp-includes/js/jquery/jquery-migrate.min.js',
				'underscore.min.js'     => ABSPATH . 'wp-includes/js/underscore.min.js',
				'backbone.min.js'       => ABSPATH . 'wp-includes/js/backbone.min.js',
				'react.min.js'          => ABSPATH . 'wp-includes/js/dist/vendor/react.min.js',
				'react-dom.min.js'      => ABSPATH . 'wp-includes/js/dist/vendor/react-dom.min.js',
			];

			$this->ensure_dir( $target_base );

			foreach ( $asset_map as $target_name => $source_path ) {
				$target_path = $target_base . $target_name;
				if ( file_exists( $target_path ) ) {
					continue;
				}

				if ( file_exists( $source_path ) ) {
					@copy( $source_path, $target_path );
				}
			}
		}

		private function ensure_dashicons_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$target_css  = $plugin_base . 'assets/vendor/dashicons/css/dashicons.min.css';
			$target_font = $plugin_base . 'assets/vendor/dashicons/fonts/';

			if ( file_exists( $target_css ) && file_exists( $target_font . 'dashicons.woff2' ) ) {
				return;
			}

			$source_css = ABSPATH . 'wp-includes/css/dashicons.min.css';
			$source_dir = ABSPATH . 'wp-includes/fonts/';

			if ( ! file_exists( $source_css ) || ! is_dir( $source_dir ) ) {
				return;
			}

			$this->ensure_dir( dirname( $target_css ) );
			$this->ensure_dir( $target_font );

			@copy( $source_css, $target_css );

			$font_files = [ 'dashicons.eot', 'dashicons.svg', 'dashicons.ttf', 'dashicons.woff', 'dashicons.woff2' ];
			foreach ( $font_files as $font_file ) {
				$source_file = $source_dir . $font_file;
				if ( file_exists( $source_file ) ) {
					@copy( $source_file, $target_font . $font_file );
				}
			}
		}

		private function ensure_eicons_assets() {
			$plugin_base = plugin_dir_path( __FILE__ );
			$target_css  = $plugin_base . 'assets/vendor/eicons/css/elementor-icons.min.css';
			$target_font = $plugin_base . 'assets/vendor/eicons/fonts/';

			if ( file_exists( $target_css ) ) {
				return;
			}

			$source_base = WP_CONTENT_DIR . '/plugins/elementor/assets/lib/eicons/';
			$source_css  = $source_base . 'css/elementor-icons.min.css';
			$source_font = $source_base . 'fonts/';

			$this->ensure_dir( dirname( $target_css ) );
			$this->ensure_dir( $target_font );

			if ( file_exists( $source_css ) ) {
				@copy( $source_css, $target_css );
			}

			if ( is_dir( $source_font ) ) {
				$font_files = glob( $source_font . '*' );
				if ( is_array( $font_files ) ) {
					foreach ( $font_files as $font_file ) {
						if ( is_file( $font_file ) ) {
							@copy( $font_file, $target_font . basename( $font_file ) );
						}
					}
				}
			}

			if ( ! file_exists( $target_css ) ) {
				$fallback_css = "/* Elementor eicons fallback placeholder */\n";
				$fallback_css .= "@font-face{font-family:eicons;src:local('Arial');}\n";
				$fallback_css .= "[class^=eicon-],[class*=\" eicon-\"]{font-family:eicons!important;}\n";
				file_put_contents( $target_css, $fallback_css );
			}
		}

		private function ensure_dir( $dir ) {
			if ( ! is_dir( $dir ) ) {
				wp_mkdir_p( $dir );
			}
		}

		public function render_settings_page() {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}

			$settings           = $this->get_settings();
			$logs               = get_option( self::LOG_KEY, [] );
			$clear_url          = wp_nonce_url( admin_url( 'options-general.php?page=WP_Melli&clear_logs=1' ), 'WP_Melli_clear_logs' );
			$quick_presets      = $this->get_quick_whitelist_presets();
			$active_tab         = isset( $_GET['tab'] ) && 'assets' === $_GET['tab'] ? 'assets' : 'general';
			$discovered_assets  = $this->get_discovered_assets();
			$custom_mappings    = $this->get_custom_asset_mappings();
			$clear_disc_url     = wp_nonce_url( admin_url( 'options-general.php?page=WP_Melli&tab=assets&WP_Melli_clear_discovered=1' ), 'WP_Melli_clear_discovered_action' );

			?>
			<div class="wrap WP_Melli-admin-wrap">
				<h1>افزایش سرعت سایت در نت ملی</h1>
				<style>
					.WP_Melli-admin-wrap {
						max-width: 1200px;
					}

					.WP_Melli-card {
						background: #ffffff;
						border: 1px solid #d6deeb;
						border-radius: 18px;
						padding: 20px 22px;
						box-shadow: 0 8px 24px rgba(5, 27, 65, 0.08);
						margin-bottom: 18px;
					}

					.WP_Melli-hero {
						background: linear-gradient(135deg, #051b41 0%, #0d2f67 100%);
						color: #ffffff;
						display: flex;
						align-items: center;
						gap: 16px;
					}

					.WP_Melli-hero h1 {
						color: #ffffff;
						margin: 0 0 6px;
						font-size: 26px;
						line-height: 1.3;
					}

					.WP_Melli-hero h2 {
						color: #fccb04;
						margin: 0 0 6px;
						font-size: 16px;
						font-weight: 600;
					}

					.WP_Melli-hero p {
						margin: 0;
						color: rgba(255, 255, 255, 0.9);
					}

					.WP_Melli-logo {
						width: 70px;
						height: 70px;
						display: flex;
						align-items: center;
						justify-content: center;
						flex-shrink: 0;
					}

					.WP_Melli-tabs {
						display: flex;
						gap: 8px;
						margin: 18px 0 14px;
						border-bottom: 2px solid #d6deeb;
						padding-bottom: 0;
					}

					.WP_Melli-tab-btn {
						display: inline-flex;
						align-items: center;
						gap: 8px;
						padding: 10px 18px;
						font-size: 14px;
						font-weight: 600;
						color: #4b586e;
						text-decoration: none;
						border-radius: 12px 12px 0 0;
						background: #eef2f7;
						transition: all 0.2s ease;
					}

					.WP_Melli-tab-btn:hover {
						background: #dbe4ef;
						color: #051b41;
					}

					.WP_Melli-tab-btn.active {
						background: #051b41;
						color: #ffffff;
					}

					.WP_Melli-tab-badge {
						display: inline-block;
						background: #fccb04;
						color: #051b41;
						font-size: 11px;
						font-weight: bold;
						padding: 2px 7px;
						border-radius: 10px;
					}

					.WP_Melli-guide {
						background: #051b41;
						color: #ffffff;
					}

					.WP_Melli-guide strong {
						color: #fccb04;
					}

					.WP_Melli-links {
						display: flex;
						flex-wrap: wrap;
						gap: 10px;
						align-items: center;
					}

					.WP_Melli-form-table th {
						width: 260px;
					}

					.WP_Melli-form-table td {
						padding: 12px 10px;
					}

					.WP_Melli-settings-form input[type="text"],
					.WP_Melli-settings-form input[type="number"],
					.WP_Melli-settings-form textarea,
					.WP_Melli-settings-form select {
						border-radius: 12px;
						border-color: #cfd6de;
						padding: 8px 10px;
					}

					.WP_Melli-settings-form textarea {
						min-height: 122px;
					}

					.WP_Melli-settings-form .button {
						border-radius: 12px;
					}

					.WP_Melli-section-title {
						font-size: 16px;
						padding: 10px 14px;
						margin: 0 0 10px;
						border-radius: 12px;
						background: #051b41;
						color: #ffffff;
					}

					.WP_Melli-section-title small {
						display: block;
						margin-top: 4px;
						color: #fccb04;
						font-size: 13px;
						font-weight: 500;
					}

					.WP_Melli-section-block {
						border: 1px solid #e4eaf4;
						border-radius: 16px;
						padding: 12px;
						margin-bottom: 14px;
					}

					.WP_Melli-quick-actions {
						display: flex;
						flex-wrap: wrap;
						gap: 8px;
					}

					.WP_Melli-badge {
						display: inline-block;
						padding: 3px 8px;
						border-radius: 8px;
						font-size: 11px;
						font-weight: bold;
					}
					.WP_Melli-badge-success { background: #dcfce7; color: #166534; }
					.WP_Melli-badge-warning { background: #fef3c7; color: #92400e; }
					.WP_Melli-badge-info    { background: #e0f2fe; color: #075985; }

					.WP_Melli-upload-modal {
						display: none;
						position: fixed;
						top: 0; left: 0; right: 0; bottom: 0;
						background: rgba(5, 27, 65, 0.65);
						z-index: 99999;
						align-items: center;
						justify-content: center;
					}
					.WP_Melli-upload-modal.open { display: flex; }
					.WP_Melli-modal-box {
						background: #fff;
						padding: 24px;
						border-radius: 16px;
						max-width: 520px;
						width: 90%;
						box-shadow: 0 20px 40px rgba(0,0,0,0.3);
					}

					.WP_Melli-log-details summary {
						font-size: 1.15em;
						font-weight: bold;
						cursor: pointer;
						display: flex;
						align-items: center;
						justify-content: space-between;
						color: #051b41;
					}

					.WP_Melli-log-toolbar {
						display: flex;
						justify-content: space-between;
						align-items: center;
						gap: 12px;
						margin-bottom: 14px;
						flex-wrap: wrap;
					}

					.WP_Melli-log-table {
						border-radius: 14px;
						overflow: hidden;
						border: 1px solid #d6deeb;
					}
				</style>

				<div class="WP_Melli-card WP_Melli-hero">
					<div class="WP_Melli-logo" aria-hidden="true">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							width="100"
							height="100"
							viewBox="0 0 24 24"
							fill="none"
							stroke="#ffffff"
							stroke-width="2"
							stroke-linecap="round"
							stroke-linejoin="round"
						>
							<path stroke="none" d="M0 0h24v24H0z" fill="none"/>
							<path d="M12 18l.01 0" />
							<path d="M9.172 15.172a4 4 0 0 1 5.656 0" />
							<path d="M6.343 12.343a7.963 7.963 0 0 1 3.864 -2.14m4.163 .155a7.965 7.965 0 0 1 3.287 2" />
							<path d="M3.515 9.515a12 12 0 0 1 3.544 -2.455m3.101 -.92a12 12 0 0 1 10.325 3.374" />
							<path d="M3 3l18 18" />
						</svg>
					</div>
					<div>
						<h1>تنظیمات افزونه وردپرس ملی (نسخه ۲.۰۱)</h1>
						<h2>مدیریت هوشمند درخواست‌ها و بومی‌سازی کتابخانه‌های خارجی</h2>
						<p>توسعه یافته اختصاصی توسط وبینیو (Webinew) برای حفظ پایداری و سرعت سایت در زمان اختلال اینترنت بین‌الملل.</p>
					</div>
				</div>

				<div class="WP_Melli-tabs">
					<a href="<?php echo esc_url( admin_url( 'options-general.php?page=WP_Melli&tab=general' ) ); ?>" class="WP_Melli-tab-btn <?php echo 'general' === $active_tab ? 'active' : ''; ?>">
						⚙️ تنظیمات فایروال و شبکه
					</a>
					<a href="<?php echo esc_url( admin_url( 'options-general.php?page=WP_Melli&tab=assets' ) ); ?>" class="WP_Melli-tab-btn <?php echo 'assets' === $active_tab ? 'active' : ''; ?>">
						📦 رصد و بومی‌سازی کتابخانه‌ها
						<?php if ( ! empty( $discovered_assets ) ) : ?>
							<span class="WP_Melli-tab-badge"><?php echo (int) count( $discovered_assets ); ?></span>
						<?php endif; ?>
					</a>
				</div>

				<?php if ( isset( $_GET['asset_status'] ) ) : ?>
					<?php if ( 'downloaded' === $_GET['asset_status'] ) : ?>
						<div class="notice notice-success is-dismissible"><p>✅ کتابخانه با موفقیت دانلود و بر روی هاست محلی شما ذخیره شد. از این پس این فایل به‌صورت خودکار از سرور داخلی لود می‌شود.</p></div>
					<?php elseif ( 'uploaded' === $_GET['asset_status'] ) : ?>
						<div class="notice notice-success is-dismissible"><p>✅ فایل کتابخانه با موفقیت آپلود شد و به جای نسخه خارجی جایگزین گردید.</p></div>
					<?php elseif ( 'removed' === $_GET['asset_status'] ) : ?>
						<div class="notice notice-info is-dismissible"><p>نسخه محلی کتابخانه حذف شد و به حالت اولیه بازگشت.</p></div>
					<?php elseif ( 'cleared' === $_GET['asset_status'] ) : ?>
						<div class="notice notice-info is-dismissible"><p>لیست کتابخانه‌های رصد شده بازنشانی گردید.</p></div>
					<?php elseif ( 'error' === $_GET['asset_status'] ) : ?>
						<div class="notice notice-error is-dismissible"><p>❌ خطا در عملیات کتابخانه: <?php echo esc_html( $_GET['err'] ?? 'نامشخص' ); ?></p></div>
					<?php endif; ?>
				<?php endif; ?>

				<?php if ( 'assets' === $active_tab ) : ?>
					<!-- تب مدیریت و رصد کتابخانه‌ها -->
					<div class="WP_Melli-card WP_Melli-guide">
						<p style="margin:0 0 8px;"><strong>راهنمای سیستم رصد و بومی‌سازی کتابخانه‌ها:</strong></p>
						<p style="margin:0 0 6px;">این سیستم به طور خودکار بررسی می‌کند که کدام فایل‌های JS و CSS قالب‌ها و افزونه‌ها از سایت‌ها یا CDNهای خارجی فراخوانی می‌شوند.</p>
						<p style="margin:0 0 6px;">شما می‌توانید با زدن دکمه <strong>«دانلود و لود محلی»</strong>، بدون نیاز به دانش برنامه‌نویسی فایل را روی هاست خود ذخیره کنید تا از این به بعد حتی در زمان قطعی کامل اینترنت جهانی، سایت با سرعت بالا و بدون ارور اجرا شود.</p>
						<p style="margin:0;">همچنین اگر فایل دانلود نشد یا نسخه تغییریافته‌ای دارید، می‌توانید فایل را مستقیماً از سیستم خود با دکمه <strong>«آپلود نسخه دستی»</strong> جایگزین کنید.</p>
					</div>

					<div class="WP_Melli-card">
						<div class="WP_Melli-log-toolbar">
							<h2 style="margin:0; font-size:18px;">کتابخانه‌های شناسایی‌شده در سایت شما</h2>
							<div>
								<button type="button" class="button button-primary" onclick="openUploadModal('', '')">➕ آپلود کتابخانه دلخواه برای آدرس خاص</button>
								<?php if ( ! empty( $discovered_assets ) ) : ?>
									<a href="<?php echo esc_url( $clear_disc_url ); ?>" class="button button-secondary" onclick="return confirm('آیا از پاکسازی تاریخچه رصد مطمئن هستید؟');">پاکسازی لیست رصد</a>
								<?php endif; ?>
							</div>
						</div>

						<?php if ( empty( $discovered_assets ) ) : ?>
							<div style="text-align:center; padding:35px 20px; color:#64748b;">
								<p style="font-size:15px; margin:0 0 8px;">هنوز کتابخانه خارجی فعالی رصد نشده است.</p>
								<small>به محض اینکه صفحات سایت (فرانت یا ادمین) باز شوند و افزونه‌ای فایل JS یا CSS خارجی فراخوانی کند، در این جدول نمایش داده می‌شود.</small>
							</div>
						<?php else : ?>
							<table class="widefat striped WP_Melli-log-table">
								<thead>
									<tr>
										<th style="width:22%;">نام و منبع افزونه/قالب</th>
										<th style="width:10%;">نوع</th>
										<th style="width:38%;">آدرس اینترنتی کتابخانه (URL)</th>
										<th style="width:12%;">وضعیت</th>
										<th style="width:18%;">اقدام</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( array_reverse( $discovered_assets ) as $item ) : ?>
										<?php
											$norm_key     = $this->normalize_asset_key( $item['src'] );
											$is_localized = ! empty( $custom_mappings[ $norm_key ] );
										?>
										<tr>
											<td>
												<strong><?php echo esc_html( $item['source_name'] ); ?></strong>
												<?php if ( ! empty( $item['handle'] ) ) : ?>
													<br><small style="color:#64748b;">هندل: <code><?php echo esc_html( $item['handle'] ); ?></code></small>
												<?php endif; ?>
											</td>
											<td>
												<span class="WP_Melli-badge <?php echo 'script' === $item['type'] ? 'WP_Melli-badge-info' : 'WP_Melli-badge-warning'; ?>">
													<?php echo 'script' === $item['type'] ? 'JS اسکریپت' : 'CSS استایل'; ?>
												</span>
											</td>
											<td style="word-break: break-all;">
												<a href="<?php echo esc_url( $item['src'] ); ?>" target="_blank" rel="noopener noreferrer">
													<code><?php echo esc_html( $item['src'] ); ?></code>
												</a>
											</td>
											<td>
												<?php if ( $is_localized ) : ?>
													<span class="WP_Melli-badge WP_Melli-badge-success">✅ لود از نسخه محلی</span>
												<?php else : ?>
													<span class="WP_Melli-badge WP_Melli-badge-warning">🌐 لود از سرور خارجی</span>
												<?php endif; ?>
											</td>
											<td>
												<?php if ( ! $is_localized ) : ?>
													<form method="post" style="display:inline-block; margin-bottom:4px;">
														<?php wp_nonce_field( 'WP_Melli_download_asset_action', 'WP_Melli_download_asset_nonce' ); ?>
														<input type="hidden" name="asset_url" value="<?php echo esc_attr( $item['src'] ); ?>">
														<button type="submit" class="button button-small button-primary">📥 دانلود و لود محلی</button>
													</form>
													<button type="button" class="button button-small button-secondary" onclick="openUploadModal('<?php echo esc_js( $item['src'] ); ?>', '<?php echo esc_js( $item['source_name'] ); ?>')">⬆️ آپلود دستی</button>
												<?php else : ?>
													<?php
														$rem_url = wp_nonce_url( admin_url( 'options-general.php?page=WP_Melli&tab=assets&WP_Melli_remove_mapping=' . urlencode( $norm_key ) ), 'WP_Melli_remove_mapping_action' );
													?>
													<a href="<?php echo esc_url( $rem_url ); ?>" class="button button-small button-link-delete" onclick="return confirm('آیا می‌خواهید نسخه محلی حذف شده و مجدداً به سرور خارجی متصل شود؟');">حذف نسخه محلی</a>
												<?php endif; ?>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>

					<!-- مودال آپلود کتابخانه دستی -->
					<div id="WP_Melli-upload-modal" class="WP_Melli-upload-modal">
						<div class="WP_Melli-modal-box">
							<h3 style="margin-top:0;">آپلود نسخه محلی کتابخانه</h3>
							<p class="description">فایل دانلود شده (js یا css) را انتخاب کنید تا به جای درخواست خارجی این فایل لود شود.</p>
							<form method="post" enctype="multipart/form-data">
								<?php wp_nonce_field( 'WP_Melli_upload_asset_action', 'WP_Melli_upload_asset_nonce' ); ?>
								<p>
									<label><strong>آدرس URL کتابخانه خارجی:</strong></label><br>
									<input type="text" id="modal-asset-url" name="asset_url" required style="width:100%; border-radius:10px; margin-top:5px;" placeholder="https://cdn.example.com/library.js">
								</p>
								<p>
									<label><strong>فایل محلی (JS یا CSS):</strong></label><br>
									<input type="file" name="custom_asset_file" accept=".js,.css" required style="margin-top:5px;">
								</p>
								<div style="display:flex; justify-content:flex-end; gap:8px; margin-top:20px;">
									<button type="button" class="button button-secondary" onclick="closeUploadModal()">انصراف</button>
									<button type="submit" class="button button-primary">ذخیره و فعال‌سازی محلی</button>
								</div>
							</form>
						</div>
					</div>

					<script>
						function openUploadModal(url, source) {
							var modal = document.getElementById('WP_Melli-upload-modal');
							var input = document.getElementById('modal-asset-url');
							if (modal && input) {
								input.value = url || '';
								modal.classList.add('open');
							}
						}
						function closeUploadModal() {
							var modal = document.getElementById('WP_Melli-upload-modal');
							if (modal) {
								modal.classList.remove('open');
							}
						}
					</script>

				<?php else : ?>
					<!-- تب عمومی و تنظیمات فایروال -->
					<div class="WP_Melli-card WP_Melli-guide">
						<p style="margin:0 0 8px;"><strong>راهنمای شروع سریع</strong></p>
						<p style="margin:0 0 6px;">1) اگر می خواهید با خیال راحت شروع کنید، حالت «غیرفعال» مناسب است و سایت بدون محدودیت روی هیچ دامنه ای کار می کند.</p>
						<p style="margin:0 0 6px;">2) اگر اینترنت بین الملل ناپایدار است، حالت «لیست سفید» کمک می کند فقط سرویس های ضروری سایت شما فعال بمانند. آنهارا بسته به نیاز به لیست اضافه کنید.</p>
						<p style="margin:0 0 6px;">3) برای بهتر شدن سرعت در زمان اختلال، «محدودسازی Timeout» را روشن کنید و مقدار 3 ثانیه را امتحان کنید.</p>
						<p style="margin:0;">4) اگر سرویس خاصی مثل پرداخت یا پیامک دیر پاسخ می دهد، مقدار Timeout را کمی بیشتر کنید (مثلا 5 ثانیه).</p>
					</div>

					<div class="WP_Melli-card WP_Melli-links">
						<a class="button button-secondary" href="https://ble.ir/join/E6mHR6mviv" target="_blank" rel="noopener noreferrer">کانال پیامرسان بله وبینیو</a>
						<a class="button button-secondary" href="https://webinew.com" target="_blank" rel="noopener noreferrer">وبسایت وبینیو</a>
						<span class="description">برای راهنماها و اطلاعیه های جدید در زمانی که صرفا پیامرسان های داخلی دردسترس هست کانال ما را دنبال کنید.</span>
					</div>

					<?php if ( isset( $_GET['logs_cleared'] ) ) : ?>
						<div class="notice notice-success is-dismissible"><p>لاگ‌ها با موفقیت پاک شدند.</p></div>
					<?php endif; ?>

					<form method="post" action="options.php" class="WP_Melli-card WP_Melli-settings-form">
						<?php settings_fields( 'WP_Melli_group' ); ?>
						
						<div class="WP_Melli-section-block">
							<h2 class="WP_Melli-section-title">۱) تنظیمات اصلی فایروال<small>درگاه کنترل دسترسی درخواست‌های خارجی</small></h2>
							<table class="form-table WP_Melli-form-table">
								<tr valign="top">
									<th scope="row">حالت کاری فایروال:</th>
									<td>
										<select name="<?php echo esc_attr( self::OPTION_KEY ); ?>[mode]" style="width: 320px;">
											<option value="disabled" <?php selected( $settings['mode'], 'disabled' ); ?>>غیرفعال (بدون محدودیت)</option>
											<option value="whitelist" <?php selected( $settings['mode'], 'whitelist' ); ?>>مسدودسازی همه (فقط مجازها از لیست سفید)</option>
											<option value="blacklist" <?php selected( $settings['mode'], 'blacklist' ); ?>>آزادسازی همه (فقط مسدودها از لیست سیاه)</option>
										</select>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">لیست سفید (Whitelist):<br><small>هر دامنه در یک خط (مثال: api.webinew.com)</small></th>
									<td>
										<textarea id="WP_Melli-whitelist-textarea" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[whitelist]" rows="5" style="width: 420px;"><?php echo esc_textarea( $settings['whitelist'] ); ?></textarea>
										<div style="margin-top: 10px;">
											<p class="description" style="margin-bottom: 8px;"><strong>افزودن سریع سایت های رایج به لیست سفید:</strong></p>
											<div class="WP_Melli-quick-actions">
												<?php foreach ( $quick_presets as $preset ) : ?>
													<button
														type="button"
														class="button button-secondary WP_Melli-quick-whitelist"
														data-domains="<?php echo esc_attr( implode( ',', $preset['domains'] ) ); ?>"
													>
														<?php echo esc_html( $preset['label'] ); ?>
													</button>
												<?php endforeach; ?>
											</div>
											<p class="description" style="margin-top: 8px;">با کلیک روی هر دکمه، دامنه های همان دسته به لیست سفید اضافه می شود (بدون ثبت تکراری).</p>
										</div>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">لیست سیاه (Blacklist):<br><small>هر دامنه در یک خط</small></th>
									<td>
										<textarea name="<?php echo esc_attr( self::OPTION_KEY ); ?>[blacklist]" rows="5" style="width: 420px;"><?php echo esc_textarea( $settings['blacklist'] ); ?></textarea>
									</td>
								</tr>
							</table>
						</div>

						<div class="WP_Melli-section-block">
							<h2 class="WP_Melli-section-title">۲) بهینه‌سازی Asset و فرانت‌اند<small>کنترل CDN، مسدودسازی هوشمند و جایگزینی محلی</small></h2>
							<table class="form-table WP_Melli-form-table">
								<tr valign="top">
									<th scope="row">جایگزینی CDN با فایل محلی:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[local_asset_rewrite]" value="yes" <?php checked( $settings['local_asset_rewrite'], 'yes' ); ?> />
											تلاش برای جایگزینی CDNهای رایج JS با نسخه محلی وردپرس (jQuery, React, Backbone, Underscore)
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">بلاک سختگیرانه Asset خارجی:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[strict_asset_block]" value="yes" <?php checked( $settings['strict_asset_block'], 'yes' ); ?> />
											اولویت مطلق با لوکال: اگر CSS/JS خارجی قابل جایگزینی نبود، سریع بلاک شود تا کندی ایجاد نشود
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">مسدودسازی Mixpanel:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[block_mixpanel]" value="yes" <?php checked( $settings['block_mixpanel'], 'yes' ); ?> />
											مسدودسازی درخواست‌های Mixpanel (از جمله `api-eu.mixpanel.com`) و جایگزینی اسکریپت با نسخه خنثی محلی
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">لود فونت Vazirmatn در فرانت:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_front_vazirmatn]" value="yes" <?php checked( $settings['enable_front_vazirmatn'], 'yes' ); ?> />
											اگر فعال شود، فونت محلی Vazirmatn افزونه در فرانت‌اند enqueue می‌شود (پیش‌فرض خاموش)
										</label>
									</td>
								</tr>
							</table>
						</div>

						<div class="WP_Melli-section-block">
							<h2 class="WP_Melli-section-title">۳) پایداری، حریم خصوصی و زمان پاسخ<small>کاهش timeout و حذف تماس‌های غیرضروری</small></h2>
							<table class="form-table WP_Melli-form-table">
								<tr valign="top">
									<th scope="row">محدودسازی Timeout درخواست‌های خارجی:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_timeout_guard]" value="yes" <?php checked( $settings['enable_timeout_guard'], 'yes' ); ?> />
											فعال‌سازی سقف زمان برای درخواست‌های HTTP خارجی
										</label>
										<p class="description" style="margin-top:6px;">اگر timeout درخواست بیشتر از مقدار زیر باشد، کاهش داده می‌شود تا درخواست‌های کند سریع‌تر fail شوند.</p>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">حداکثر Timeout (ثانیه):</th>
									<td>
										<input type="number" min="1" max="30" step="1" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[max_request_timeout]" value="<?php echo esc_attr( $settings['max_request_timeout'] ); ?>" style="width:100px;" />
										<p class="description">پیشنهاد: ۳ ثانیه. پیش‌فرض افزونه روی ۳ است ولی این قابلیت برای حفظ سازگاری نسخه‌های قبلی به‌صورت پیش‌فرض غیرفعال است.</p>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">تلمتری وردپرس:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[disable_telemetry]" value="yes" <?php checked( $settings['disable_telemetry'], 'yes' ); ?> />
											جلوگیری از ارسال اطلاعات به سرورهای وردپرس (wordpress.org)
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">جلوگیری از بروزرسانی‌های خودکار:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[disable_updates]" value="yes" <?php checked( $settings['disable_updates'], 'yes' ); ?> />
											غیرفعال کردن جستجو برای آپدیت هسته، قالب‌ها و افزونه‌ها
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">استثنا بروزرسانی برای لیست سفید بالا و سرور های داخلی:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[allow_whitelisted_updates]" value="yes" <?php checked( $settings['allow_whitelisted_updates'], 'yes' ); ?> />
											برای مثال با روشن گذاشتن این گزینه افزونه ها از مخزن که قطع هست بروزرسانی دریافت نمیکنند ولی از مارکت های ایرانی و مثلا افزونه های وبینیو که سرور داخل دارند بروزرسانی دریافت میکنند
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">سرویس گراواتار:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[disable_gravatar]" value="yes" <?php checked( $settings['disable_gravatar'], 'yes' ); ?> />
											مسدودسازی گراواتار و جایگزینی با عکس لوکال
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">لینک جایگزین گراواتار:</th>
									<td>
										<input type="text" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[gravatar_url]" value="<?php echo esc_url( $settings['gravatar_url'] ); ?>" style="width: 420px;" />
										<p class="description">اگر گراواتار مسدود شود، این تصویر جایگزین پروفایل کاربران خواهد شد.</p>
									</td>
								</tr>
							</table>
						</div>

						<div class="WP_Melli-section-block">
							<h2 class="WP_Melli-section-title">۴) گزارش‌گیری و لاگ‌ها<small>کنترل حجم لاگ‌ها و ردیابی خطاها</small></h2>
							<table class="form-table WP_Melli-form-table">
								<tr valign="top">
									<th scope="row">ثبت لاگ درخواست‌ها:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[enable_logging]" value="yes" <?php checked( $settings['enable_logging'], 'yes' ); ?> />
											فعال‌سازی ثبت درخواست‌های مسدود شده (فقط در زمان نیاز به عیب‌یابی فعال کنید)
										</label>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">نگهداری لاگ‌ها:</th>
									<td>
										<select name="<?php echo esc_attr( self::OPTION_KEY ); ?>[log_retention_days]">
											<option value="1" <?php selected( $settings['log_retention_days'], '1' ); ?>>۱ روز</option>
											<option value="3" <?php selected( $settings['log_retention_days'], '3' ); ?>>۳ روز</option>
											<option value="7" <?php selected( $settings['log_retention_days'], '7' ); ?>>۷ روز</option>
											<option value="15" <?php selected( $settings['log_retention_days'], '15' ); ?>>۱۵ روز</option>
											<option value="30" <?php selected( $settings['log_retention_days'], '30' ); ?>>۳۰ روز</option>
										</select>
										<p class="description">لاگ‌های قدیمی‌تر از این زمان به‌صورت خودکار حذف می‌شوند.</p>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">حداکثر تعداد لاگ:</th>
									<td>
										<input type="number" min="50" max="2000" step="10" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[log_max_entries]" value="<?php echo esc_attr( $settings['log_max_entries'] ); ?>" style="width:120px;" />
										<p class="description">برای سبک ماندن دیتابیس، فقط آخرین تعداد لاگ نگهداری می‌شود.</p>
									</td>
								</tr>
								<tr valign="top">
									<th scope="row">لاگ رویدادهای Asset:</th>
									<td>
										<label>
											<input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[log_asset_events]" value="yes" <?php checked( $settings['log_asset_events'], 'yes' ); ?> />
											ثبت رویدادهای rewrite/bypass برای CSS و JS (پیش‌فرض خاموش برای کاهش فشار)
										</label>
									</td>
								</tr>
							</table>
						</div>
						
						<?php submit_button( 'ذخیره تمامی تنظیمات' ); ?>
					</form>

					<script>
						document.addEventListener('DOMContentLoaded', function () {
							var textarea = document.getElementById('WP_Melli-whitelist-textarea');
							if (!textarea) {
								return;
							}

							var quickButtons = document.querySelectorAll('.WP_Melli-quick-whitelist');
							quickButtons.forEach(function (button) {
								button.addEventListener('click', function () {
									var currentLines = textarea.value
										.split(/\r?\n/)
										.map(function (line) { return line.trim().toLowerCase(); })
										.filter(Boolean);

									var map = {};
									currentLines.forEach(function (domain) {
										map[domain] = true;
									});

									var domains = (button.getAttribute('data-domains') || '')
										.split(',')
										.map(function (domain) { return domain.trim().toLowerCase(); })
										.filter(Boolean);

									domains.forEach(function (domain) {
										if (!map[domain]) {
											currentLines.push(domain);
											map[domain] = true;
										}
									});

									textarea.value = currentLines.join('\n');
									textarea.dispatchEvent(new Event('change'));
								});
							});
						});
					</script>

					<details class="WP_Melli-card WP_Melli-log-details">
						<summary>
							<span>مشاهده لاگ درخواست‌های مسدود شده (کلیک کنید)</span>
						</summary>
						
						<div style="margin-top: 20px;">
							<div class="WP_Melli-log-toolbar">
								<p class="description">لاگ‌ها به‌صورت خودکار محدود شده‌اند. برای جلوگیری از پر شدن دیتابیس می‌توانید آنها را پاک کنید.</p>
								<a href="<?php echo esc_url( $clear_url ); ?>" class="button button-secondary" onclick="return confirm('آیا از پاک کردن لاگ‌ها مطمئن هستید؟');">پاک کردن لاگ‌ها</a>
							</div>
							
							<table class="widefat striped WP_Melli-log-table">
								<thead>
									<tr>
										<th style="width: 15%;">زمان</th>
										<th style="width: 20%;">دلیل مسدودسازی</th>
										<th style="width: 20%;">میزبان (Host)</th>
										<th style="width: 45%;">آدرس (URL) کامل</th>
									</tr>
								</thead>
								<tbody>
									<?php if ( empty( $logs ) ) : ?>
										<tr>
											<td colspan="4" style="text-align: center;">هیچ درخواستی تا کنون مسدود نشده است.</td>
										</tr>
									<?php else : ?>
										<?php foreach ( array_reverse( $logs ) as $log ) : ?>
											<tr>
												<td><?php echo esc_html( $log['time'] ); ?></td>
												<td><code><?php echo esc_html( $log['mode'] ); ?></code></td>
												<td><strong><?php echo esc_html( $log['host'] ); ?></strong></td>
												<td style="word-break: break-all;"><code><?php echo esc_url( $log['url'] ); ?></code></td>
											</tr>
										<?php endforeach; ?>
									<?php endif; ?>
								</tbody>
							</table>
						</div>
					</details>
				<?php endif; ?>
			</div>
			<?php
		}
		public function start_output_buffer() {
			$settings = $this->get_settings();
			
			// فقط در صورتی که فایروال افزونه فعال باشد بافر را استارت می‌زنیم تا منابع هدر نرود
			if ( $settings['mode'] !== 'disabled' || 'yes' === $settings['strict_asset_block'] ) {
				ob_start( [ $this, 'filter_html_output' ] );
			}
		}

		public function filter_html_output( $buffer ) {
			if ( empty( $buffer ) ) {
				return $buffer;
			}

			$settings = $this->get_settings();

			// فیلتر کردن تگ‌های <link> (مثل فایل‌های CSS هاردکد شده قالب‌ها)
			$buffer = preg_replace_callback( '/<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*>/i', function( $matches ) use ( $settings ) {
				$url = $matches[1];
				$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
				
				if ( $this->should_block_hardcoded_asset( $url, $host, $settings, 'style' ) ) {
					return ''; // حذف کامل تگ لینک از HTML خروجی
				}
				return $matches[0];
			}, $buffer );

			// فیلتر کردن تگ‌های <script> (مثل فایل‌های JS هاردکد شده)
			$buffer = preg_replace_callback( '/<script\s+[^>]*src=["\']([^"\']+)["\'][^>]*>[\s\S]*?<\/script>/i', function( $matches ) use ( $settings ) {
				$url = $matches[1];
				$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );

				if ( $this->should_block_hardcoded_asset( $url, $host, $settings, 'script' ) ) {
					return ''; // حذف کامل تگ اسکریپت از HTML خروجی
				}
				return $matches[0];
			}, $buffer );

			return $buffer;
		}

		private function should_block_hardcoded_asset( $url, $host, $settings, $type ) {
			if ( empty( $host ) ) {
				return false;
			}
			if ( $this->is_same_site_host( $host ) ) {
				return false;
			}

			// چک کردن قوانین اختصاصی مثل Mixpanel
			if ( 'yes' === $settings['block_mixpanel'] && $this->is_mixpanel_host( $host ) ) {
				$this->log_request( $url, $host, "blocked_hardcoded_{$type}_mixpanel" );
				return true;
			}

			// اعمال قوانین لیست سیاه و سفید افزونه
			if ( $settings['mode'] === 'blacklist' ) {
				if ( $this->is_blacklisted_asset_host( $host, $settings ) ) {
					$this->log_request( $url, $host, "blocked_hardcoded_{$type}_blacklist" );
					return true;
				}
			} elseif ( $settings['mode'] === 'whitelist' ) {
				$whitelist = array_map( 'trim', explode( "\n", (string) ( $settings['whitelist'] ?? '' ) ) );
				if ( ! $this->host_in_list( $host, $whitelist ) && ! $this->is_local_host( $host ) ) {
					$this->log_request( $url, $host, "blocked_hardcoded_{$type}_whitelist" );
					return true;
				}
			}

			// بررسی حالت مسدودسازی سخت‌گیرانه (Strict)
			if ( $this->should_block_external_assets( $host, $settings ) ) {
				$this->log_request( $url, $host, "blocked_hardcoded_{$type}_strict" );
				return true;
			}

			return false;
		}

		public function get_discovered_assets() {
			$assets = get_option( self::DISCOVERED_ASSETS_OPTION, [] );
			return is_array( $assets ) ? $assets : [];
		}

		public function get_custom_asset_mappings() {
			$mappings = get_option( self::CUSTOM_MAPPINGS_OPTION, [] );
			return is_array( $mappings ) ? $mappings : [];
		}

		public function get_custom_asset_replacement( $src ) {
			$norm_src = $this->normalize_asset_key( $src );
			$mappings = $this->get_custom_asset_mappings();

			if ( ! empty( $mappings[ $norm_src ] ) ) {
				$mapped = $mappings[ $norm_src ];
				if ( ! empty( $mapped['local_url'] ) && ! empty( $mapped['local_path'] ) && file_exists( $mapped['local_path'] ) ) {
					return $mapped['local_url'];
				}
			}

			return '';
		}

		public function record_discovered_asset( $src, $handle, $type, $host, $path ) {
			$src = trim( (string) $src );
			if ( '' === $src ) {
				return;
			}

			$discovered = $this->get_discovered_assets();
			$key = $this->normalize_asset_key( $src );

			$already_mapped = false;
			$mappings = $this->get_custom_asset_mappings();
			if ( ! empty( $mappings[ $key ] ) ) {
				$mapped = $mappings[ $key ];
				if ( ! empty( $mapped['local_path'] ) && file_exists( $mapped['local_path'] ) ) {
					$already_mapped = true;
				}
			}

			$source_info = $this->guess_asset_source( $handle, $src );

			$discovered[ $key ] = [
				'src'          => $src,
				'handle'       => sanitize_key( (string) $handle ),
				'type'         => 'style' === $type ? 'style' : 'script',
				'host'         => sanitize_text_field( (string) $host ),
				'path'         => sanitize_text_field( (string) $path ),
				'source_name'  => $source_info['name'],
				'source_type'  => $source_info['type'],
				'is_localized' => $already_mapped,
				'last_seen'    => current_time( 'mysql' ),
			];

			if ( count( $discovered ) > 200 ) {
				$discovered = array_slice( $discovered, -200, null, true );
			}

			update_option( self::DISCOVERED_ASSETS_OPTION, $discovered, 'no' );
		}

		private function normalize_asset_key( $url ) {
			$url = trim( (string) $url );
			if ( 0 === strpos( $url, '//' ) ) {
				$url = 'https:' . $url;
			}

			$parts = wp_parse_url( $url );
			if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
				return strtolower( $url );
			}

			$host = strtolower( (string) $parts['host'] );
			$path = isset( $parts['path'] ) ? (string) $parts['path'] : '';
			return $host . $path;
		}

		private function guess_asset_source( $handle, $src ) {
			$handle_clean = strtolower( (string) $handle );
			$src_clean    = strtolower( (string) $src );

			if ( false !== strpos( $handle_clean, 'elementor' ) || false !== strpos( $src_clean, 'elementor' ) ) {
				return [ 'name' => 'افزونه المنتور (Elementor)', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'woocommerce' ) || false !== strpos( $handle_clean, 'wc-' ) || false !== strpos( $src_clean, 'woocommerce' ) ) {
				return [ 'name' => 'افزونه ووکامرس (WooCommerce)', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'wpforms' ) || false !== strpos( $src_clean, 'wpforms' ) ) {
				return [ 'name' => 'افزونه فرم‌ساز WPForms', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'cf7' ) || false !== strpos( $handle_clean, 'contact-form-7' ) || false !== strpos( $src_clean, 'contact-form-7' ) ) {
				return [ 'name' => 'افزونه Contact Form 7', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'slider-revolution' ) || false !== strpos( $handle_clean, 'revslider' ) ) {
				return [ 'name' => 'افزونه اسلایدر روولوشن (RevSlider)', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'yoast' ) || false !== strpos( $src_clean, 'yoast' ) ) {
				return [ 'name' => 'افزونه یواست سئو (Yoast SEO)', 'type' => 'plugin' ];
			}
			if ( false !== strpos( $handle_clean, 'rank-math' ) || false !== strpos( $src_clean, 'rank-math' ) ) {
				return [ 'name' => 'افزونه رنک مث (Rank Math)', 'type' => 'plugin' ];
			}

			if ( ! empty( $handle ) ) {
				return [ 'name' => 'هندل: ' . esc_html( $handle ), 'type' => 'handle' ];
			}

			$host = (string) wp_parse_url( $src, PHP_URL_HOST );
			return [ 'name' => 'منبع خارجی (' . ( $host ?: 'ناشناخته' ) . ')', 'type' => 'external' ];
		}

		public function handle_asset_manager_actions() {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}

			// دانلود خودکار کتابخانه خارجی
			if ( isset( $_POST['WP_Melli_download_asset_nonce'] ) && wp_verify_nonce( $_POST['WP_Melli_download_asset_nonce'], 'WP_Melli_download_asset_action' ) ) {
				$asset_url = isset( $_POST['asset_url'] ) ? esc_url_raw( trim( $_POST['asset_url'] ) ) : '';
				if ( ! empty( $asset_url ) ) {
					$result = $this->download_external_asset( $asset_url );
					$status = is_wp_error( $result ) ? 'error&err=' . urlencode( $result->get_error_message() ) : 'downloaded';
					wp_safe_redirect( admin_url( 'options-general.php?page=WP_Melli&tab=assets&asset_status=' . $status ) );
					exit;
				}
			}

			// آپلود دستی کتابخانه توسط کاربر
			if ( isset( $_POST['WP_Melli_upload_asset_nonce'] ) && wp_verify_nonce( $_POST['WP_Melli_upload_asset_nonce'], 'WP_Melli_upload_asset_action' ) ) {
				$asset_url = isset( $_POST['asset_url'] ) ? esc_url_raw( trim( $_POST['asset_url'] ) ) : '';
				if ( ! empty( $asset_url ) && ! empty( $_FILES['custom_asset_file'] ) ) {
					$result = $this->upload_custom_asset( $asset_url, $_FILES['custom_asset_file'] );
					$status = is_wp_error( $result ) ? 'error&err=' . urlencode( $result->get_error_message() ) : 'uploaded';
					wp_safe_redirect( admin_url( 'options-general.php?page=WP_Melli&tab=assets&asset_status=' . $status ) );
					exit;
				}
			}

			// حذف جایگزینی محلی کتابخانه
			if ( isset( $_GET['WP_Melli_remove_mapping'] ) && isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'WP_Melli_remove_mapping_action' ) ) {
				$key = sanitize_text_field( $_GET['WP_Melli_remove_mapping'] );
				$mappings = $this->get_custom_asset_mappings();
				if ( isset( $mappings[ $key ] ) ) {
					if ( ! empty( $mappings[ $key ]['local_path'] ) && file_exists( $mappings[ $key ]['local_path'] ) ) {
						@unlink( $mappings[ $key ]['local_path'] );
					}
					unset( $mappings[ $key ] );
					update_option( self::CUSTOM_MAPPINGS_OPTION, $mappings, 'no' );
				}
				wp_safe_redirect( admin_url( 'options-general.php?page=WP_Melli&tab=assets&asset_status=removed' ) );
				exit;
			}

			// پاکسازی لیست دارایی‌های رصد شده
			if ( isset( $_GET['WP_Melli_clear_discovered'] ) && isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'WP_Melli_clear_discovered_action' ) ) {
				delete_option( self::DISCOVERED_ASSETS_OPTION );
				wp_safe_redirect( admin_url( 'options-general.php?page=WP_Melli&tab=assets&asset_status=cleared' ) );
				exit;
			}
		}

		private function download_external_asset( $url ) {
			$url = trim( (string) $url );
			if ( 0 === strpos( $url, '//' ) ) {
				$url = 'https:' . $url;
			}

			$path = (string) wp_parse_url( $url, PHP_URL_PATH );
			$ext  = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, [ 'js', 'css' ], true ) ) {
				return new WP_Error( 'invalid_type', 'فقط فایل‌های جاوااسکریپت (js) و استایل (css) پشتیبانی می‌شوند.' );
			}

			// دور زدن فیلترهای بلاک خود افزونه جهت دانلود امن در سرور
			$response = wp_remote_get( $url, [
				'timeout'    => 15,
				'sslverify'  => false,
				'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
			] );

			if ( is_wp_error( $response ) ) {
				return $response;
			}

			$code = wp_remote_retrieve_response_code( $response );
			if ( 200 !== (int) $code ) {
				return new WP_Error( 'download_failed', 'پاسخ سرور مقصد در هنگام دانلود فایل: ' . (int) $code );
			}

			$content = wp_remote_retrieve_body( $response );
			if ( empty( $content ) ) {
				return new WP_Error( 'empty_body', 'فایل دریافت شده خالی است.' );
			}

			return $this->save_local_asset_file( $url, $path, $ext, $content );
		}

		private function upload_custom_asset( $url, $uploaded_file ) {
			if ( empty( $uploaded_file['tmp_name'] ) || ! is_uploaded_file( $uploaded_file['tmp_name'] ) ) {
				return new WP_Error( 'upload_failed', 'فایل ارسالی یافت نشد یا معتبر نیست.' );
			}

			$filename = sanitize_file_name( $uploaded_file['name'] );
			$ext      = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, [ 'js', 'css' ], true ) ) {
				return new WP_Error( 'invalid_extension', 'فقط پسوندهای .js و .css مجاز هستند.' );
			}

			$content = file_get_contents( $uploaded_file['tmp_name'] );
			if ( false === $content || '' === trim( $content ) ) {
				return new WP_Error( 'file_empty', 'محتوای فایل آپلود شده خالی است.' );
			}

			$path = (string) wp_parse_url( $url, PHP_URL_PATH );
			return $this->save_local_asset_file( $url, $path, $ext, $content );
		}

		private function save_local_asset_file( $url, $orig_path, $ext, $content ) {
			$upload_dir = wp_upload_dir();
			$target_dir = trailingslashit( $upload_dir['basedir'] ) . 'wp-melli-assets/' . ( 'js' === $ext ? 'js/' : 'css/' );
			$this->ensure_dir( $target_dir );

			$clean_basename = sanitize_file_name( basename( $orig_path ) );
			if ( empty( $clean_basename ) || ! preg_match( '/\.(js|css)$/i', $clean_basename ) ) {
				$clean_basename = 'asset-' . substr( md5( $url ), 0, 10 ) . '.' . $ext;
			} else {
				$clean_basename = substr( md5( $url ), 0, 8 ) . '-' . $clean_basename;
			}

			$target_file = $target_dir . $clean_basename;
			$written     = file_put_contents( $target_file, $content );
			if ( false === $written ) {
				return new WP_Error( 'write_failed', 'خطا در ذخیره فایل در مسیر uploads وردپرس.' );
			}

			$target_url = trailingslashit( $upload_dir['baseurl'] ) . 'wp-melli-assets/' . ( 'js' === $ext ? 'js/' : 'css/' ) . $clean_basename;

			$key = $this->normalize_asset_key( $url );
			$mappings = $this->get_custom_asset_mappings();
			$mappings[ $key ] = [
				'original_url' => $url,
				'local_url'    => $target_url,
				'local_path'   => $target_file,
				'ext'          => $ext,
				'updated_at'   => current_time( 'mysql' ),
			];

			update_option( self::CUSTOM_MAPPINGS_OPTION, $mappings, 'no' );

			$discovered = $this->get_discovered_assets();
			if ( isset( $discovered[ $key ] ) ) {
				$discovered[ $key ]['is_localized'] = true;
				update_option( self::DISCOVERED_ASSETS_OPTION, $discovered, 'no' );
			}

			return true;
		}

		private function init_github_updater() {
			add_filter( 'site_transient_update_plugins', [ $this, 'check_github_update' ] );
			add_filter( 'plugins_api', [ $this, 'github_plugin_information' ], 20, 3 );
			add_filter( 'upgrader_source_selection', [ $this, 'rename_github_plugin_folder' ], 10, 4 );
		}

		private function get_github_repo_slug() {
			return 'EhsanGhasimi/wp-melli';
		}

		public function check_github_update( $transient ) {
			if ( empty( $transient->checked ) ) {
				return $transient;
			}

			$release = $this->fetch_github_latest_release();
			if ( ! $release || empty( $release['tag_name'] ) ) {
				return $transient;
			}

			$latest_version  = ltrim( $release['tag_name'], 'vV' );
			$current_version = self::PLUGIN_VERSION;

			if ( version_compare( $current_version, $latest_version, '<' ) ) {
				$plugin_basename = plugin_basename( __FILE__ );
				$download_url    = ! empty( $release['zipball_url'] ) ? $release['zipball_url'] : "https://github.com/{$this->get_github_repo_slug()}/archive/refs/tags/{$release['tag_name']}.zip";

				if ( ! empty( $release['assets'] ) && is_array( $release['assets'] ) ) {
					foreach ( $release['assets'] as $asset ) {
						if ( ! empty( $asset['browser_download_url'] ) && preg_match( '/\.zip$/i', $asset['browser_download_url'] ) ) {
							$download_url = $asset['browser_download_url'];
							break;
						}
					}
				}

				$obj              = new stdClass();
				$obj->slug        = 'wp-melli';
				$obj->plugin      = $plugin_basename;
				$obj->new_version = $latest_version;
				$obj->url         = "https://github.com/{$this->get_github_repo_slug()}";
				$obj->package     = $download_url;
				$obj->icons       = [
					'default' => plugin_dir_url( __FILE__ ) . 'user.jpg',
				];

				$transient->response[ $plugin_basename ] = $obj;
			}

			return $transient;
		}

		public function github_plugin_information( $result, $action, $args ) {
			if ( 'plugin_information' !== $action || empty( $args->slug ) || 'wp-melli' !== $args->slug ) {
				return $result;
			}

			$release = $this->fetch_github_latest_release();
			if ( ! $release ) {
				return $result;
			}

			$plugin_basename = plugin_basename( __FILE__ );
			$download_url    = ! empty( $release['zipball_url'] ) ? $release['zipball_url'] : "https://github.com/{$this->get_github_repo_slug()}/archive/refs/tags/{$release['tag_name']}.zip";

			$res                = new stdClass();
			$res->name          = 'وردپرس ملی (wp-melli)';
			$res->slug          = 'wp-melli';
			$res->version       = ltrim( $release['tag_name'], 'vV' );
			$res->author        = '<a href="https://webinew.com">Ehsan Ghasimi | Webinew</a>';
			$res->homepage      = "https://github.com/{$this->get_github_repo_slug()}";
			$res->requires      = '5.0';
			$res->tested        = '6.9';
			$res->requires_php  = '7.4';
			$res->download_link = $download_url;
			$res->sections      = [
				'description' => 'افزونه وردپرس ملی، بهینه‌ساز عملکرد سایت در زمان قطعی و اختلال اینترنت بین‌الملل و بومی‌ساز کتابخانه‌های خارجی وردپرس.',
				'changelog'   => ! empty( $release['body'] ) ? nl2br( esc_html( $release['body'] ) ) : 'به‌روزرسانی‌های جدید افزونه وردپرس ملی.',
			];

			return $res;
		}

		public function rename_github_plugin_folder( $source, $remote_source, $upgrader, $hook_extra = [] ) {
			if ( ! isset( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== plugin_basename( __FILE__ ) ) {
				return $source;
			}

			global $wp_filesystem;
			$correct_slug   = dirname( plugin_basename( __FILE__ ) );
			$corrected_path = trailingslashit( $remote_source ) . $correct_slug;

			if ( untrailingslashit( $source ) === untrailingslashit( $corrected_path ) ) {
				return $source;
			}

			if ( $wp_filesystem->move( $source, $corrected_path ) ) {
				return trailingslashit( $corrected_path );
			}

			return $source;
		}

		private function fetch_github_latest_release() {
			$transient_key = 'wp_melli_github_release_cache';
			$cached = get_transient( $transient_key );
			if ( false !== $cached ) {
				return $cached;
			}

			$url = "https://api.github.com/repos/{$this->get_github_repo_slug()}/releases/latest";
			$response = wp_remote_get( $url, [
				'timeout'    => 10,
				'user-agent' => 'WP-Melli-GitHub-Updater',
				'headers'    => [
					'Accept' => 'application/vnd.github.v3+json',
				],
			] );

			if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				return false;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );
			if ( ! is_array( $data ) || empty( $data['tag_name'] ) ) {
				return false;
			}

			set_transient( $transient_key, $data, 2 * HOUR_IN_SECONDS );
			return $data;
		}
	}

	new WP_Melli_HTTP_Control();
}

// A plugin from Webinew Team in webinew.com