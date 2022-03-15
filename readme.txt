=== Authing Authentication ===
Contributors: willin
Home link: https://authing.cn
Tags: authing, authentication
Requires at least: 3.0.1
Tested up to: 5.9.1
Requires PHP: 5.2.4
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

Enables Authing integration for WordPress. This plugin requires that you have an Authing account. You can create a development account for free at https://authing.cn/ .

== Installation ==

Simply install and activate the plugin. There will be an Authing item in your admin menu with full instructions on how to configure your Authing integration. The client key and secret that you provide will be stored in the database, unless you add them to your wp-config.php. Those values get sent over to the Authing server URL that you provide in order to interact with your Authing app and authenticate the user. The response is not cached in WordPress, and the Authing tokens automatically expire.

== Frequently Asked Questions ==

== Screenshots ==

== Changelog ==

= 0.0.1 =

* Initial commit

== Upgrade Notice ==
