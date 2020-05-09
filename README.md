# f19-msci3300-g6
Group 6 repository for South Liberty Public Library project

Create Table Materials
CREATE TABLE group7_materials(
MaterialID int(11) NOT NULL AUTO_INCREMENT,
MaterialClass varchar(25) NOT NULL,
CallNumber varchar(255) NOT NULL,
Title varchar(255) NOT NULL,
Author varchar(255),
Publisher varchar(255) NOT NULL,
Copyright int(4),
ISBN int(15) NOT NULL,
DateAdded DATETIME NOT NULL,
LastModified DATETIME NOT NULL,
PRIMARY KEY (MaterialID)
)ENGINE=InnoDB AUTO_INCREMENT=1;

USE f19_msci3300;

CREATE TABLE group7_patron(
	patronId int(11) NOT NULL AUTO_INCREMENT,
	firtName varchar(255) NOT NULL,
	lastName varchar(255) NOT NULL,
	birthdate DATE NOT NULL,
	address1 varchar(255),
	address2 varchar(255),
	city varchar(255) NOT NULL,
	state char(2) NOT NULL,
	zip int(5) NOT NULL,
	phoneNumber1 int(10),
	phoneNumber2 int(10),
	email varchar(255),
PRIMARY KEY ('patronId')
) ENGINE =InnoDB AUTO_INCREMENT =1;

INSERT INTO group7_patron(firstName, lastName, birthdate, address1, address2, city, state, zip, phonenumber1, email)
VALUES ('Robert', 'California', '1/1/1961', 'Apt. # 100', '123 Main St.', 'South Liberty', 'IA', '54345', '3195550001', 'ceo@sabre.com');
