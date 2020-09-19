# Enzoic PHP Client Library

## TOC

This README covers the following topics:

- [Installation](#installation)
- [API Overview](#api-overview)
- [The Enzoic constructor](#the-enzoic-constructor)

## Installation

```sh
$ composer require monolog/monolog
```

## API Overview

Below is some simple example code which demonstrates the usage of the API. 

```php
<?php

use Enzoic\Enzoic;
use Enzoic\PasswordType;

// Create a new Enzoic instance - this is our primary interface for making API calls
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);

// Check whether a password has been compromised
$passwordCompromised = $enzoic->checkPassword('password-to-test'); 

if ($passwordCompromised === true) {
    echo 'Password is compromised';
}
else {
    echo 'Password is not compromised';
}

// Check whether a specific set of credentials are compromised
$credentialsCompromised = $enzoic->checkCredentials('test@enzoic.com', 'password-to-test'); 

 if ($credentialsCompromised === true) {
    echo 'Credentials are compromised';
}
else {
    echo 'Credentials are not compromised';
}

// checkCredentials has optional parameters offering more control over performance.
//
// lastCheckDate: 
// A DateTime containing the timestamp of the last credentials check you performed for this user.
// If the date/time you provide for the last check is greater than the timestamp Enzoic has for the last
// breach affecting this user, the check will not be performed.  This can be used to substantially increase performance 
// after the initial call.
//
// excludeHashAlgorithms: 
// An array of PasswordTypes to ignore when calculating hashes for the credentials check.   
// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this
// call against security.
//

// should be set to the last time you checked credentials for this user for performance
$dateOfLastCredentialsCheck = new DateTime('2020-07-01T02:05:03.000Z');

// let's exclude BCrypt and PHPBB3 
$excludeHashAlgorithms = [ PasswordType::BCrypt, PasswordType::PHPBB3 ];

$credentialsCompromised = $enzoic->checkCredentials('test@enzoic.com', 'password-to-test', 
    $dateOfLastCredentialsCheck, $excludeHashAlgorithms);
    
if ($credentialsCompromised === true) {
    echo 'Credentials are compromised';
}
else {
    echo 'Credentials are not compromised';
}

// get all exposures for the given user
$userExposures = $enzoic->getExposuresForUser('eicar_1@enzoic.com');

echo count($userExposures).' exposures found for eicar_1@enzoic.com';
    
// now get the full details for the first exposure returned in the list
$exposureDetails = $enzoic->getExposureDetails($userExposures[0]);

echo 'First exposure for test@enzoic.com was '.$exposureDetails->{'title'};
```

More information in reference format can be found below.

## The Enzoic constructor

The standard constructor takes the API key and secret you were issued on Enzoic signup.

```php
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API host, you may call the overloaded constructor and pass the host you were provided.

```php
$enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET, "api-alt.enzoic.com");
```
