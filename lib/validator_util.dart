library validator_util;

import 'dart:async';

const String _kEmailRule =
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?)*$";

const String kriteria = r"^0[8][0-9]*$";

//const String _kMin8CharsOneLetterOneNumber = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$";
const String _kMin8CharsOneLetterOneNumberOnSpecialCharacter =
    r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*]).{8,}$";
const String kRegex =
    r"^(?:(?=.*?[A-Z])(?:(?=.*?[0-9])(?=.*?[-!@#$%^&*()_[\]{},.<>+=])|(?=.*?[a-z])(?:(?=.*?[0-9])|(?=.*?[-!@#$%^&*()_[\]{},.<>+=])))|(?=.*?[a-z])(?=.*?[0-9])(?=.*?[-!@#$%^&*()_[\]{},.<>+=]))[A-Za-z0-9!@#$%^&*()_[\]{},.<>+=-]{7,50}$";
// const String _kMin8CharsOneUpperLetterOneLowerLetterOnNumber = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$";
//const String _kMin8CharsOneUpperOneLowerOneNumberOneSpecial = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$";
//const String _kMin8Max10OneUpperOneLowerOneNumberOneSpecial = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$";
const String _kMin8Character = r"^.{8,}$";
const String _kMinContainNumber = r"^.*[0-9].*$";
const String _kMinContainUppercase = r"^.*[A-Z].*$";
const String _kMinContainLowercase = r"^.*[a-z].*$";
const String _kMinContainSpecialCharacter = r"^.*[!@#$%^&*].*$";
const String _kKtpRule = r"^[0-9]{16}$";
const String nameRules = r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$";

// EmailValidatorUtil
final StreamTransformer<String, String> validateEmailUtil =
    StreamTransformer<String, String>.fromHandlers(handleData: (email, sink) {
  final RegExp emailExp = new RegExp(_kEmailRule);

  if (!emailExp.hasMatch(email) || email.isEmpty) {
    sink.addError('Format email salah');
  } else {
    sink.add(email);
  }
});

String isEmailValid(String value) {
  final RegExp emailExp = new RegExp(_kEmailRule);

  if (value.isEmpty) {
    return 'Email harus diisi';
  } else if (!emailExp.hasMatch(value)) {
    return 'Format email salah';
  }
  return "";
}

// EmptyValidatorUtil
final StreamTransformer<String, String> validateEmptyUtil =
    StreamTransformer<String, String>.fromHandlers(
        handleData: (inputString, sink) {
  if (inputString.isEmpty) {
    sink.addError('Tidak boleh kosong');
  } else {
    sink.add(inputString);
  }
});

String isEmpty(String value) {
  if (value.isEmpty) return 'Tidak boleh kosong';

  return "";
}

String isLoginValidator(String value, String inputType) {
  if (value.isEmpty) {
    return 'Tidak boleh kosong';
  } else {
    var messageEmail = isEmailValid(value);

    if (inputType == 'username') {
      if (isNumeric(value)) {
        var messagePhone = isPhoneValid(value);
        if (messagePhone.isNotEmpty) {
          return messagePhone;
        }
      } else {
        if (messageEmail.isNotEmpty) {
          return messageEmail;
        }
      }
    }

    var messagePassword = isPasswordValid(value);
    if (messagePassword.isNotEmpty && inputType == 'password') {
      return messagePassword;
    }
  }

  return "";
}

bool isNumeric(String s) {
  if (s == null) {
    return false;
  }
  return double.parse(s, (e) => null) != null;
}

//PhoneValidatorUtil
final StreamTransformer<String, String> validatePhoneUtil =
    StreamTransformer<String, String>.fromHandlers(handleData: (phone, sink) {
  final RegExp phoneExp = new RegExp(kriteria);

  if (!phoneExp.hasMatch(phone)) {
    sink.addError('Nomor handphone kamu salah');
  } else if (phone.length < 10 || phone.length > 13) {
    sink.addError('Nomor Handphone minimal 10 digit');
  } else {
    sink.add(phone);
  }
});

String isPhoneValid(String value) {
  final RegExp phoneExp = new RegExp(kriteria);

  if (value.isEmpty)
    return 'Nomor Handphone harus diisi';
  else if (!phoneExp.hasMatch(value)) return 'Nomor handphone kamu salah';
  return "";
}

String isPhoneMatch(String value, String main) {
  if (value.isEmpty) {
    return 'Nomor Handphone harus diisi';
  } else if (0 != value.compareTo(main)) {
    return "Nomor Telepon tidak sama";
  }
  return "";
}

//PasswordValidatorUtil
final StreamTransformer<String, String> validatePassword =
    StreamTransformer<String, String>.fromHandlers(
        handleData: (password, sink) {
  final RegExp passwordExp =
      new RegExp(_kMin8CharsOneLetterOneNumberOnSpecialCharacter);

  if (!passwordExp.hasMatch(password)) {
    sink.addError(
        'Password paling tidak memiliki satu huruf besar, satu huruf kecil, satu angka, dan satu karakter spesial [!@#\$%^&*]');
  } else {
    sink.add(password);
  }
});

final StreamTransformer<String, String> validateSelfRegSetPassword =
    StreamTransformer<String, String>.fromHandlers(
        handleData: (password, sink) {
  final RegExp passwordExp =
      new RegExp(_kMin8CharsOneLetterOneNumberOnSpecialCharacter);

  if (!passwordExp.hasMatch(password)) {
    sink.addError(
        'Password paling tidak memiliki satu huruf besar, satu huruf kecil, satu angka, dan satu karakter spesial [!@#\$%^&*]');
  } else {
    sink.add(password);
  }
});

final StreamTransformer<String, String> validateConfirmPassword =
    StreamTransformer<String, String>.fromHandlers(
        handleData: (password, sink) {
  final RegExp passwordExp = new RegExp(_kMinContainSpecialCharacter);

  if (!passwordExp.hasMatch(password)) {
    sink.addError('Password tidak sesuai');
  } else {
    sink.add(password);
  }
});

final StreamTransformer<String, bool> validatePwdMin8Char =
    StreamTransformer<String, bool>.fromHandlers(handleData: (password, sink) {
  final RegExp passwordExp = RegExp(_kMin8Character);
  if (passwordExp.hasMatch(password)) {
    sink.add(true);
  } else {
    sink.add(false);
  }
});

final StreamTransformer<String, bool> validatePwdMinContainNumber =
    StreamTransformer<String, bool>.fromHandlers(handleData: (password, sink) {
  final RegExp passwordExp = RegExp(_kMinContainNumber);
  if (passwordExp.hasMatch(password) && password.isNotEmpty) {
    sink.add(true);
  } else {
    sink.add(false);
  }
});

final StreamTransformer<String, bool> validatePwdMinContainUppercase =
    StreamTransformer<String, bool>.fromHandlers(handleData: (password, sink) {
  final RegExp passwordExp = RegExp(_kMinContainUppercase);
  if (passwordExp.hasMatch(password) && password.isNotEmpty) {
    sink.add(true);
  } else {
    sink.add(false);
  }
});

final StreamTransformer<String, bool> validatePwdMinContainLowercase =
    StreamTransformer<String, bool>.fromHandlers(handleData: (password, sink) {
  final RegExp passwordExp = RegExp(_kMinContainLowercase);
  if (passwordExp.hasMatch(password) && password.isNotEmpty) {
    sink.add(true);
  } else {
    sink.add(false);
  }
});

final StreamTransformer<String, bool> validatePwdContainSpecialChar =
    StreamTransformer<String, bool>.fromHandlers(handleData: (password, sink) {
  final RegExp passwordExp = RegExp(_kMinContainSpecialCharacter);
  if (passwordExp.hasMatch(password) && password.isNotEmpty) {
    sink.add(true);
  } else {
    sink.add(false);
  }
  // if (checkSpecialCharacter(password) && password.isNotEmpty) {
  //   sink.add(true);
  // } else {
  //   sink.add(false);
  // }
});

String isPasswordValid(String value) {
  final RegExp emailExp =
      new RegExp(_kMin8CharsOneLetterOneNumberOnSpecialCharacter);

  if (value.isEmpty) {
    return 'Kata Sandi harus diisi';
  } else if (!emailExp.hasMatch(value)) {
    return 'Password paling tidak memiliki satu huruf besar, satu huruf kecil, satu angka, dan satu karakter spesial [!@#\$%^&*]';
  }
  return "";
}

String isPasswordMatch(String password, String _confirmPassword) {
  if (_confirmPassword.isEmpty) {
    return 'Kata Sandi harus diisi';
  } else if (0 != password.compareTo(_confirmPassword)) {
    return 'Password konfirmasi tidak sama dengan password baru';
  }
  return "";
}

bool checkSpecialCharacter(String value) {
  bool s;
  value.runes.forEach((int i) {
    //var character = String.fromCharCode(i);

    if (i > 32 && i < 48) {
      s = true;
    } else if (i > 57 && i < 65) {
      s = true;
    } else if (i > 90 && i < 97) {
      s = true;
    } else if (i == 123 || i == 125) {
      s = true;
    }
  });

  return s;
}

//KtpValidatorUtil
final StreamTransformer<String, String> validateKtpUtil =
    StreamTransformer<String, String>.fromHandlers(handleData: (ktp, sink) {
  final RegExp ktpExp = new RegExp(_kKtpRule);

  if (ktp.isEmpty) {
    sink.addError('No KTP harus diisi');
  } else if (!ktpExp.hasMatch(ktp)) {
    sink.addError('Nomor KTP salah');
  } else if (checkNikYear(ktp) == false) {
    sink.addError('Umur harus diatas atau sama dengan 21 tahun');
  } else if (checkNikDateMonth(ktp) == false) {
    sink.addError('Nomor KTP salah');
  } else if (checkNikSequence(ktp) == false) {
    sink.addError('Nomor KTP salah');
  } else {
    sink.add(ktp);
  }
});

String isKtpValid(String value) {
  final RegExp ktpExp = new RegExp(_kKtpRule);

  if (value.isEmpty) {
    return 'No KTP harus diisi';
  } else if (!ktpExp.hasMatch(value)) {
    return 'Nomor KTP salah';
  }
  return "";
}

bool checkNikYear(String nik) {
  var tanggal = nik.substring(6, 8);
  var bulan = nik.substring(8, 10);
  var tahun = nik.substring(10, 12);

  var dateNow = DateTime.now();
  int yyyy = dateNow.year;

  var yy = int.parse(yyyy.toString().substring(2, 4));

  int numBulanLahir = int.parse(bulan);
  int numTahunLahir = int.parse(tahun);

  int numTahunLahirYYYY;

  if (numTahunLahir < yy) {
    numTahunLahirYYYY = int.parse('200${numTahunLahir.toString()}');
  } else if (numTahunLahir > yy) {
    numTahunLahirYYYY = int.parse('19${numTahunLahir.toString()}');
  } else {
    numTahunLahirYYYY = int.parse('20${yy.toString()}');
  }

  var birthDate;
  var diffInMs;
  var diffInYear;

  var bulanPertama = '01';
  var bulanTerakhir = '12';

  if (numBulanLahir > 0 && numBulanLahir < 13) {
    birthDate = '${numTahunLahirYYYY.toString()}-$bulan-$tanggal';
    diffInMs =
        DateTime.now().difference(DateTime.parse(birthDate)).inMilliseconds;
    diffInYear = (diffInMs / (1000 * 60 * 60 * 24 * 365.25)).floor();
  } else if (numBulanLahir == 0) {
    birthDate = '${numTahunLahirYYYY.toString()}-$bulanPertama-$tanggal';
    diffInMs =
        DateTime.now().difference(DateTime.parse(birthDate)).inMilliseconds;
    diffInYear = (diffInMs / (1000 * 60 * 60 * 24 * 365.25)).floor();
  } else if (numBulanLahir >= 13) {
    birthDate = '${numTahunLahirYYYY.toString()}-$bulanTerakhir-$tanggal';
    diffInMs =
        DateTime.now().difference(DateTime.parse(birthDate)).inMilliseconds;
    diffInYear = (diffInMs / (1000 * 60 * 60 * 24 * 365.25)).floor();
  } else {
    //do nothing
  }

  if (diffInYear >= 17) {
    return true;
  } else {
    return false;
  }
}

bool checkNikDateMonth(String nik) {
  var tanggal = nik.substring(6, 8);
  var bulan = nik.substring(8, 10);

  int numTanggalLahir = int.parse(tanggal);
  int numBulanLahir = int.parse(bulan);

  if (numTanggalLahir > 0 &&
      numTanggalLahir < 32 &&
      numBulanLahir > 0 &&
      numBulanLahir < 13) {
    return true;
  } else if (numTanggalLahir > 40 &&
      numTanggalLahir < 72 &&
      numBulanLahir > 0 &&
      numBulanLahir < 13) {
    return true;
  } else {
    return false;
  }
}

bool checkNikSequence(String nik) {
  var sequence = nik.substring(12, 16);

  if (sequence == '0000') {
    return false;
  } else {
    return true;
  }
}

//NameValidatorUtil
final StreamTransformer<String, String> validateNameUtil =
    StreamTransformer<String, String>.fromHandlers(handleData: (name, sink) {
  final RegExp nameExp = new RegExp(nameRules);

  if (name.isEmpty) {
    sink.addError('Nama lengkap harus diisi');
  } else if (!nameExp.hasMatch(name)) {
    sink.addError('Format Nama tidak sesuai');
  } else {
    sink.add(name);
  }
});

String isNameValid(String value) {
  final RegExp emailExp = new RegExp(nameRules);

  if (value.isEmpty) {
    return 'Nama lengkap harus diisi';
  } else if (!emailExp.hasMatch(value)) {
    return 'Format Nama tidak sesuai';
  }
  return '';
}
