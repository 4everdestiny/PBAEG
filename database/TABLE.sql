drop table if exists vulnerability_detection;

create table vulnerability_detection(
    id int unsigned not null auto_increment primary key,
    time DATETIME,
    binary_name varchar(100),
    binary_path varchar(500),
    finish_detect boolean,
    time_consuming float,
    vulnerability_type varchar(30),
    payload_path varchar(500),
    architecture varchar(10),
    NX boolean,
    Canary boolean,
    PIE boolean,
    RELRO varchar(20)
);

drop table if exists vulnerability_detection_IOT;

create table vulnerability_detection_IOT(
    id int unsigned not null auto_increment primary key,
    time DATETIME,
    binary_name varchar(100),
    binary_path varchar(500),
    finish_detect boolean,
    time_consuming float,
    vulnerability_type varchar(30),
    payload_path varchar(500),
    architecture varchar(10),
    NX boolean,
    Canary boolean,
    PIE boolean,
    RELRO varchar(20),
    exploit_method varchar(30),
    technique_used varchar(20)
);
