drop table if exists users;
drop table if exists teams;
drop table if exists nodes;

create table users(
  `username` varchar(30) NOT NULL,
  `password` varchar(50) NOT NULL,
  `type` INT NOT NULL,
  `team_id` INT DEFAULT '-1',
  PRIMARY KEY (`username`)
);

create table teams(
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` varchar(30) NOT NULL,
  `desc` varchar(300)
);

create table nodes(
  `name` varchar(30) NOT NULL,
  `host` varchar(30) NOT NULL,
  `port` INT NOT NULL,
  `username` varchar(30),
  `password` varchar(50),
  `environment` INT NOT NULL,
   PRIMARY KEY (`name`,`host`)
);

insert into users values('admin', 'admin', 0, -1);
