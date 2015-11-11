/*
 * Refactored to share as much as possible from the primary PasswordMaker_MD5 algorithm while keeping 0.6 api compatilbility.
 * Bug: if the charCodeAt value is less than 15 on the first iteration of the loop, the value is still appended as a 0 as
 * the first character in the resulting string.
 */

var PasswordMaker_MD5 = require('./md5');

if (typeof PasswordMaker_MD5_V6 !== "object") {
    var PasswordMaker_MD5_V6 = {
        hex_md5: function(key) {
            return this.buggy2hex(PasswordMaker_MD5.rstr_md5(key));
        },
        hex_hmac_md5: function(key, data) {
            return this.buggy2hex(PasswordMaker_MD5.rstr_hmac_md5(key, data));
        },

        buggy2hex: function(input) {
            var hex = "0123456789abcdef",
                output = "";
            for (var i = 0; i < input.length; i++) {
                var x = input.charCodeAt(i);
                output += hex.charAt((x >> 4) & 0xF);
                output += hex.charAt(x & 0xF);
            }
            return output;
        }
    };
}

module.exports = PasswordMaker_MD5_V6;
