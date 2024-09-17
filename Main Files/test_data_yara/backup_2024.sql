-- Database: 'client_data'

CREATE TABLE `clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `account_status` varchar(50) DEFAULT 'Active',
  PRIMARY KEY (`id`)
);

INSERT INTO `clients` (`id`, `name`, `email`, `phone`, `account_status`) VALUES
(1, 'Omega Industries', 'contact@omega.com', '123-456-7890', 'Active'),
(2, 'Alpha Corp', 'info@alpha.com', '098-765-4321', 'Inactive'),
(3, 'Beta Solutions', 'support@beta.com', '111-222-3333', 'Pending');
