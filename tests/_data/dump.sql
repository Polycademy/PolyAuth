/* Replace this file with actual dump of your database */

-- phpMyAdmin SQL Dump
-- version 4.0.4
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jul 02, 2013 at 05:43 PM
-- Server version: 5.6.12-log
-- PHP Version: 5.4.16

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

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
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=6 ;

--
-- Dumping data for table `auth_permission`
--

INSERT INTO `auth_permission` (`permission_id`, `name`, `description`, `added_on`, `updated_on`) VALUES
(1, 'admin_create', 'Creating administration resources.', '2013-07-02 00:14:55', '2013-07-02 00:14:55'),
(2, 'admin_read', 'Viewing administration resources.', '2013-07-02 00:14:55', '2013-07-02 00:14:55'),
(3, 'admin_update', 'Editing administration resources.', '2013-07-02 00:14:55', '2013-07-02 00:14:55'),
(4, 'admin_delete', 'Deleting administration resources.', '2013-07-02 00:14:55', '2013-07-02 00:14:55'),
(5, 'public_read', 'Viewing public resources.', '2013-07-02 00:14:55', '2013-07-02 00:14:55');

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
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `auth_role`
--

INSERT INTO `auth_role` (`role_id`, `name`, `description`, `added_on`, `updated_on`) VALUES
(1, 'admin', 'Site Administrators', '2013-07-02 00:14:55', '2013-07-02 00:14:55'),
(2, 'member', 'General Members', '2013-07-02 00:14:55', '2013-07-02 00:14:55');

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
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=6 ;

--
-- Dumping data for table `auth_role_permissions`
--

INSERT INTO `auth_role_permissions` (`role_permission_id`, `role_id`, `permission_id`, `added_on`) VALUES
(1, 1, 1, '2013-07-02 00:14:55'),
(2, 1, 2, '2013-07-02 00:14:55'),
(3, 1, 3, '2013-07-02 00:14:55'),
(4, 1, 4, '2013-07-02 00:14:55'),
(5, 2, 5, '2013-07-02 00:14:55');

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
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

--
-- Dumping data for table `auth_subject_role`
--

INSERT INTO `auth_subject_role` (`subject_role_id`, `subject_id`, `role_id`) VALUES
(1, 1, 1),
(2, 1, 2);

-- --------------------------------------------------------

--
-- Table structure for table `chat`
--

CREATE TABLE IF NOT EXISTS `chat` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `usersId` int(9) DEFAULT NULL,
  `roomId` int(9) DEFAULT NULL,
  `message` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `courses`
--

CREATE TABLE IF NOT EXISTS `courses` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) DEFAULT NULL,
  `startingDate` date DEFAULT NULL,
  `daysDuration` smallint(6) DEFAULT NULL,
  `times` varchar(100) DEFAULT NULL,
  `numberOfApplications` smallint(6) DEFAULT NULL,
  `numberOfStudents` smallint(6) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` mediumint(8) NOT NULL AUTO_INCREMENT,
  `ipAddress` varbinary(16) DEFAULT NULL,
  `identity` varchar(100) DEFAULT NULL,
  `lastAttempt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `migrations`
--

CREATE TABLE IF NOT EXISTS `migrations` (
  `version` bigint(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `migrations`
--

INSERT INTO `migrations` (`version`) VALUES
(3);

-- --------------------------------------------------------

--
-- Table structure for table `user_accounts`
--

CREATE TABLE IF NOT EXISTS `user_accounts` (
  `id` mediumint(8) NOT NULL AUTO_INCREMENT,
  `ipAddress` varbinary(16) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `passwordChange` tinyint(1) DEFAULT '0',
  `email` varchar(100) DEFAULT NULL,
  `activationCode` varchar(40) DEFAULT NULL,
  `forgottenCode` varchar(40) DEFAULT NULL,
  `forgottenDate` datetime DEFAULT NULL,
  `autoCode` varchar(40) DEFAULT NULL,
  `autoDate` datetime DEFAULT NULL,
  `createdOn` datetime DEFAULT NULL,
  `lastLogin` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT '0',
  `banned` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- Dumping data for table `user_accounts`
--

INSERT INTO `user_accounts` (`id`, `ipAddress`, `username`, `password`, `passwordChange`, `email`, `activationCode`, `forgottenCode`, `forgottenDate`, `autoCode`, `autoDate`, `createdOn`, `lastLogin`, `active`, `banned`) VALUES
(1, '\0\0', 'administrator', '$2y$10$EiqipvSt3lnD//nchj4u9OgOTL9R3J4AbZ5bUVVrh.Tq/gmc5xIvS', 0, 'admin@admin.com', '', NULL, NULL, 'w01LgeSk8pO9B03Gv0sE', '2013-07-01 14:45:41', '2013-07-01 14:14:55', '2013-07-01 14:45:41', 1, 0);

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