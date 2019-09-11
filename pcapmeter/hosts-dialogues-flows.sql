-- MySQL dump 10.13  Distrib 8.0.17, for Linux (x86_64)
--
-- Host: localhost    Database: tese
-- ------------------------------------------------------
-- Server version	8.0.17

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `Dialogues`
--

DROP TABLE IF EXISTS `Dialogues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `Dialogues` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `src_host_id` int(10) unsigned NOT NULL,
  `dst_host_id` int(10) unsigned NOT NULL,
  `src_ip` varbinary(16) NOT NULL,
  `dst_ip` varbinary(16) NOT NULL,
  `dialogue_start_time` datetime(6) DEFAULT NULL,
  `dialogue_end_time` datetime(6) DEFAULT NULL,
  `n_fwd_flows` int(10) unsigned DEFAULT NULL,
  `n_bwd_flows` int(10) unsigned DEFAULT NULL,
  `fwd_flows_rate` float unsigned DEFAULT NULL,
  `bwd_flows_rate` float unsigned DEFAULT NULL,
  `total_flow_duration` float unsigned DEFAULT NULL,
  `mean_flow_duration` float unsigned DEFAULT NULL,
  `std_flow_duration` float unsigned DEFAULT NULL,
  `var_flow_duration` float unsigned DEFAULT NULL,
  `max_flow_duration` float unsigned DEFAULT NULL,
  `min_flow_duration` float unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_dialogue_id` (`src_ip`,`dst_ip`) COMMENT 'Make dialogue id (ip1-ip2) unique.',
  KEY `fk_host_src_dialogue_idx` (`src_host_id`),
  KEY `fk_host_dst_dialogue_idx` (`dst_host_id`),
  CONSTRAINT `fk_host_dst_dialogue` FOREIGN KEY (`dst_host_id`) REFERENCES `Hosts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_host_src_dialogue` FOREIGN KEY (`src_host_id`) REFERENCES `Hosts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=20888 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Dialogues`
--

LOCK TABLES `Dialogues` WRITE;
/*!40000 ALTER TABLE `Dialogues` DISABLE KEYS */;
/*!40000 ALTER TABLE `Dialogues` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Flows`
--

DROP TABLE IF EXISTS `Flows`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `Flows` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `dialogue_id` int(10) unsigned NOT NULL,
  `transport_protocol` varchar(8) NOT NULL,
  `src_ip` varbinary(16) NOT NULL,
  `dst_ip` varbinary(16) NOT NULL,
  `src_port` smallint(2) unsigned NOT NULL,
  `dst_port` smallint(2) unsigned NOT NULL,
  `sep_counter` int(10) unsigned NOT NULL,
  `flow_start_time` datetime(6) DEFAULT NULL,
  `flow_end_time` datetime(6) DEFAULT NULL,
  `flow_duration` float unsigned DEFAULT NULL,
  `fwd_header_len_total` float unsigned DEFAULT NULL,
  `bwd_header_len_total` float unsigned DEFAULT NULL,
  `flow_pkt_size_mean` float unsigned DEFAULT NULL,
  `flow_pkt_size_std` float unsigned DEFAULT NULL,
  `flow_pkt_size_max` float unsigned DEFAULT NULL,
  `flow_pkt_size_min` float unsigned DEFAULT NULL,
  `fwd_pkt_size_mean` float unsigned DEFAULT NULL,
  `fwd_pkt_size_std` float unsigned DEFAULT NULL,
  `fwd_pkt_size_max` float unsigned DEFAULT NULL,
  `fwd_pkt_size_min` float unsigned DEFAULT NULL,
  `bwd_pkt_size_mean` float unsigned DEFAULT NULL,
  `bwd_pkt_size_std` float unsigned DEFAULT NULL,
  `bwd_pkt_size_max` float unsigned DEFAULT NULL,
  `bwd_pkt_size_min` float unsigned DEFAULT NULL,
  `fwd_n_pkts` int(10) unsigned DEFAULT NULL,
  `bwd_n_pkts` int(10) unsigned DEFAULT NULL,
  `flow_pkts_per_sec` float unsigned DEFAULT NULL,
  `fwd_pkts_per_sec` float unsigned DEFAULT NULL,
  `bwd_pkts_per_sec` float unsigned DEFAULT NULL,
  `flow_bytes_per_sec` float unsigned DEFAULT NULL,
  `flow_pkt_len_total` float unsigned DEFAULT NULL,
  `flow_pkt_len_mean` float unsigned DEFAULT NULL,
  `flow_pkt_len_std` float unsigned DEFAULT NULL,
  `flow_pkt_len_var` float unsigned DEFAULT NULL,
  `flow_pkt_len_max` float unsigned DEFAULT NULL,
  `flow_pkt_len_min` float unsigned DEFAULT NULL,
  `fwd_pkt_len_total` float unsigned DEFAULT NULL,
  `fwd_pkt_len_mean` float unsigned DEFAULT NULL,
  `fwd_pkt_len_std` float unsigned DEFAULT NULL,
  `fwd_pkt_len_var` float unsigned DEFAULT NULL,
  `fwd_pkt_len_max` float unsigned DEFAULT NULL,
  `fwd_pkt_len_min` float unsigned DEFAULT NULL,
  `bwd_pkt_len_total` float unsigned DEFAULT NULL,
  `bwd_pkt_len_mean` float unsigned DEFAULT NULL,
  `bwd_pkt_len_std` float unsigned DEFAULT NULL,
  `bwd_pkt_len_var` float unsigned DEFAULT NULL,
  `bwd_pkt_len_max` float unsigned DEFAULT NULL,
  `bwd_pkt_len_min` float unsigned DEFAULT NULL,
  `flow_n_data_pkts` int(10) unsigned DEFAULT NULL,
  `fwd_n_data_pkts` int(10) unsigned DEFAULT NULL,
  `bwd_n_data_pkts` int(10) unsigned DEFAULT NULL,
  `flow_iat_total` float unsigned DEFAULT NULL,
  `flow_iat_mean` float unsigned DEFAULT NULL,
  `flow_iat_std` float unsigned DEFAULT NULL,
  `flow_iat_max` float unsigned DEFAULT NULL,
  `flow_iat_min` float unsigned DEFAULT NULL,
  `fwd_iat_total` float unsigned DEFAULT NULL,
  `fwd_iat_mean` float unsigned DEFAULT NULL,
  `fwd_iat_std` float unsigned DEFAULT NULL,
  `fwd_iat_max` float unsigned DEFAULT NULL,
  `fwd_iat_min` float unsigned DEFAULT NULL,
  `bwd_iat_total` float unsigned DEFAULT NULL,
  `bwd_iat_mean` float unsigned DEFAULT NULL,
  `bwd_iat_std` float unsigned DEFAULT NULL,
  `bwd_iat_max` float unsigned DEFAULT NULL,
  `bwd_iat_min` float unsigned DEFAULT NULL,
  `flow_df_count` int(10) unsigned DEFAULT NULL,
  `flow_mf_count` int(10) unsigned DEFAULT NULL,
  `flow_fin_count` int(10) unsigned DEFAULT NULL,
  `flow_syn_count` int(10) unsigned DEFAULT NULL,
  `flow_rst_count` int(10) unsigned DEFAULT NULL,
  `flow_psh_count` int(10) unsigned DEFAULT NULL,
  `flow_ack_count` int(10) unsigned DEFAULT NULL,
  `flow_urg_count` int(10) unsigned DEFAULT NULL,
  `flow_ece_count` int(10) unsigned DEFAULT NULL,
  `flow_cwr_count` int(10) unsigned DEFAULT NULL,
  `fwd_df_count` int(10) unsigned DEFAULT NULL,
  `fwd_mf_count` int(10) unsigned DEFAULT NULL,
  `fwd_fin_count` int(10) unsigned DEFAULT NULL,
  `fwd_syn_count` int(10) unsigned DEFAULT NULL,
  `fwd_rst_count` int(10) unsigned DEFAULT NULL,
  `fwd_psh_count` int(10) unsigned DEFAULT NULL,
  `fwd_ack_count` int(10) unsigned DEFAULT NULL,
  `fwd_urg_count` int(10) unsigned DEFAULT NULL,
  `fwd_ece_count` int(10) unsigned DEFAULT NULL,
  `fwd_cwr_count` int(10) unsigned DEFAULT NULL,
  `bwd_df_count` int(10) unsigned DEFAULT NULL,
  `bwd_mf_count` int(10) unsigned DEFAULT NULL,
  `bwd_fin_count` int(10) unsigned DEFAULT NULL,
  `bwd_syn_count` int(10) unsigned DEFAULT NULL,
  `bwd_rst_count` int(10) unsigned DEFAULT NULL,
  `bwd_psh_count` int(10) unsigned DEFAULT NULL,
  `bwd_ack_count` int(10) unsigned DEFAULT NULL,
  `bwd_urg_count` int(10) unsigned DEFAULT NULL,
  `bwd_ece_count` int(10) unsigned DEFAULT NULL,
  `bwd_cwr_count` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_flow_id` (`transport_protocol`,`src_ip`,`dst_ip`,`src_port`,`dst_port`),
  KEY `fk_dialogue_flow_idx` (`dialogue_id`),
  CONSTRAINT `fk_dialogue_flow` FOREIGN KEY (`dialogue_id`) REFERENCES `Dialogues` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=32284 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Flows`
--

LOCK TABLES `Flows` WRITE;
/*!40000 ALTER TABLE `Flows` DISABLE KEYS */;
/*!40000 ALTER TABLE `Flows` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Hosts`
--

DROP TABLE IF EXISTS `Hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `Hosts` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `ip` varbinary(16) NOT NULL,
  `n_dialogues` int(10) unsigned DEFAULT NULL,
  `rate_dialogues` float unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_host_id` (`ip`)
) ENGINE=InnoDB AUTO_INCREMENT=92737 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Hosts`
--

LOCK TABLES `Hosts` WRITE;
/*!40000 ALTER TABLE `Hosts` DISABLE KEYS */;
/*!40000 ALTER TABLE `Hosts` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-09-11 19:38:27
