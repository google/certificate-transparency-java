# Certificate Transparency: Java Code

![Maven badge](https://maven-badges.herokuapp.com/maven-central/org.certificate-transparency/ctlog/badge.png)

This repository holds Java code related to [Certificate
Transparency](https://www.certificate-transparency.org/) (CT).

## Installation

To install the library to your local Maven repository, simply execute:

```shell
git clone https://github.com/google/certificate-transparency-java
cd certificate-transparency-java
mvn install
```

To add this dependency to your project's POM:

```xml
<dependency>
    <groupId>org.certificate-transparency</groupId>
    <artifactId>ctlog</artifactId>
    <version>0.1.0</version>
    <scope>compile</scope>
</dependency>
```

## Known Issues

- It does not support Android. Alternatives exist for use on Android, such as:
  - https://github.com/anonyome/certificate-transparency-android
  - https://github.com/Babylonpartners/certificate-transparency-android

