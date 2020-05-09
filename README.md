# msci3300

Create Table cheyao_casemap
CREATE TABLE cheyao_casemap(
states varchar(2) NOT NULL ,
cases int(11) NOT NULL,
recovered int(11) NOT NULL,
deaths int(11) NOT NULL,
fatality varchar(25) NOT NULL,
PRIMARY KEY (states)
)ENGINE=InnoDB ;

USE msci3300;

CREATE TABLE cheyao_casesummary(
	location varchar(45) NOT NULL ,
	totalCases int(11) NOT NULL,
	totalRecovered int(11) NOT NULL,
	totalDeaths int(11) NOT NULL,
	fatality varchar(25) NOT NULL,
	date date,
	
PRIMARY KEY ('location')
) ENGINE =InnoDB ;

INSERT INTO cheyao_casesummary(location, totalCases, totalRecovered, totalDeaths, fatality, date)
VALUES ('US', '1319678', '183063', '78316', '2.1%', '2020-05-08');
