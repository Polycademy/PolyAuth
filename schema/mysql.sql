-- phpMyAdmin SQL Dump
-- version 4.0.4
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 02, 2013 at 06:42 AM
-- Server version: 5.6.12-log
-- PHP Version: 5.4.16

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `test`
--
CREATE DATABASE IF NOT EXISTS `test` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
USE `test`;

-- --------------------------------------------------------

--
-- Table structure for table `auth_permission`
--

CREATE TABLE IF NOT EXISTS `auth_permission` (
  `permission_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(32) CHARACTER SET utf8 NOT NULL,
  `description` text CHARACTER SET utf8,
  `added_on` datetime DEFAULT NULL,
  `updated_on` datetime DEFAULT NULL,
  PRIMARY KEY (`permission_id`),
  UNIQUE KEY `uniq_perm` (`name`) USING BTREE
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=6 ;

--
-- Dumping data for table `auth_permission`
--

INSERT INTO `auth_permission` (`permission_id`, `name`, `description`, `added_on`, `updated_on`) VALUES
(1, 'admin_create', 'Creating administration resources.', '2013-12-02 17:41:41', '2013-12-02 17:41:41'),
(2, 'admin_read', 'Viewing administration resources.', '2013-12-02 17:41:41', '2013-12-02 17:41:41'),
(3, 'admin_update', 'Editing administration resources.', '2013-12-02 17:41:41', '2013-12-02 17:41:41'),
(4, 'admin_delete', 'Deleting administration resources.', '2013-12-02 17:41:41', '2013-12-02 17:41:41'),
(5, 'public_read', 'Viewing public resources.', '2013-12-02 17:41:41', '2013-12-02 17:41:41');

-- --------------------------------------------------------

--
-- Table structure for table `auth_role`
--

CREATE TABLE IF NOT EXISTS `auth_role` (
  `role_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 NOT NULL,
  `description` text CHARACTER SET utf8,
  `added_on` datetime DEFAULT NULL,
  `updated_on` datetime DEFAULT NULL,
  PRIMARY KEY (`role_id`),
  UNIQUE KEY `uniq_name` (`name`) USING BTREE
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `auth_role`
--

INSERT INTO `auth_role` (`role_id`, `name`, `description`, `added_on`, `updated_on`) VALUES
(1, 'admin', 'Site Administrators', '2013-12-02 17:41:41', '2013-12-02 17:41:41'),
(2, 'member', 'General Members', '2013-12-02 17:41:41', '2013-12-02 17:41:41');

-- --------------------------------------------------------

--
-- Table structure for table `auth_role_permissions`
--

CREATE TABLE IF NOT EXISTS `auth_role_permissions` (
  `role_permission_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `role_id` int(10) unsigned NOT NULL,
  `permission_id` int(10) unsigned NOT NULL,
  `added_on` datetime DEFAULT NULL,
  PRIMARY KEY (`role_permission_id`),
  KEY `fk_role` (`role_id`) USING BTREE,
  KEY `fk_permission` (`permission_id`) USING BTREE
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=6 ;

--
-- Dumping data for table `auth_role_permissions`
--

INSERT INTO `auth_role_permissions` (`role_permission_id`, `role_id`, `permission_id`, `added_on`) VALUES
(1, 1, 1, '2013-12-02 17:41:41'),
(2, 1, 2, '2013-12-02 17:41:41'),
(3, 1, 3, '2013-12-02 17:41:41'),
(4, 1, 4, '2013-12-02 17:41:41'),
(5, 2, 5, '2013-12-02 17:41:41');

-- --------------------------------------------------------

--
-- Table structure for table `auth_subject_role`
--

CREATE TABLE IF NOT EXISTS `auth_subject_role` (
  `subject_role_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `subject_id` int(10) unsigned NOT NULL,
  `role_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`subject_role_id`),
  UNIQUE KEY `role_id` (`role_id`,`subject_id`) USING BTREE,
  KEY `fk_subjectid` (`subject_id`) USING BTREE,
  KEY `fk_roleid` (`role_id`) USING BTREE
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `auth_subject_role`
--

INSERT INTO `auth_subject_role` (`subject_role_id`, `subject_id`, `role_id`) VALUES
(1, 1, 1),
(2, 1, 2);

-- --------------------------------------------------------

--
-- Table structure for table `external_providers`
--

CREATE TABLE IF NOT EXISTS `external_providers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` int(11) NOT NULL,
  `provider` varchar(100) NOT NULL,
  `externalIdentifier` text NOT NULL,
  `tokenObject` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ipAddress` varbinary(16) NOT NULL,
  `identity` varchar(100) NOT NULL,
  `lastAttempt` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `user_accounts`
--

CREATE TABLE IF NOT EXISTS `user_accounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ipAddress` varbinary(16) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `passwordChange` tinyint(1) NOT NULL DEFAULT '0',
  `email` varchar(100) NOT NULL,
  `activationCode` varchar(40) NOT NULL,
  `forgottenCode` varchar(40) NOT NULL,
  `forgottenDate` datetime NOT NULL,
  `autoCode` varchar(40) NOT NULL,
  `autoDate` datetime NOT NULL,
  `createdOn` datetime NOT NULL,
  `lastLogin` datetime NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT '0',
  `banned` tinyint(1) NOT NULL DEFAULT '0',
  `sharedKey` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Dumping data for table `user_accounts`
--

INSERT INTO `user_accounts` (`id`, `ipAddress`, `username`, `password`, `passwordChange`, `email`, `activationCode`, `forgottenCode`, `forgottenDate`, `autoCode`, `autoDate`, `createdOn`, `lastLogin`, `active`, `banned`, `sharedKey`) VALUES
(1, '\0\0', 'administrator', '$2y$10$EiqipvSt3lnD//nchj4u9OgOTL9R3J4AbZ5bUVVrh.Tq/gmc5xIvS', 0, 'admin@admin.com', '', '', '0000-00-00 00:00:00', '', '0000-00-00 00:00:00', '2013-12-02 17:41:40', '2013-12-02 17:41:40', 1, 0, '');

--
-- Constraints for dumped tables
--

--
-- Constraints for table `auth_role_permissions`
--
ALTER TABLE `auth_role_permissions`
  ADD CONSTRAINT `auth_role_permissions_ibfk_1` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`permission_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `auth_role_permissions_ibfk_2` FOREIGN KEY (`role_id`) REFERENCES `auth_role` (`role_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `auth_subject_role`
--
ALTER TABLE `auth_subject_role`
  ADD CONSTRAINT `auth_subject_role_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `auth_role` (`role_id`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;