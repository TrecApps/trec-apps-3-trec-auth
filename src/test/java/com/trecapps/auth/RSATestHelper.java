package com.trecapps.auth;

public class RSATestHelper {

    // Note: These are test keys - DO NOT USE THEM IN THE ACTUAL APPLICATION!
    public static final String publicKeyValue =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMvViSSRUt6x+wFN374WI2b3MguIk+" +
                    "MuSTSnq1f9I3sZulGEiOXffaFiKlecuewcPGbzdr1HecWdIGQVlfuRY61WzpR0XOAn" +
                    "XKycCBt0Nuuilfn6EtEGKyaobZ8W4k7OnVC0ZwhLiCTwj/nsVp7dptksXsiO3rduSm" +
                    "nnC+rTV7jnCczo6ESKcZazOvK0CrB8ZYIw/0grGcDKlOLyEJCxqRUTdfgKJb16O6pu" +
                    "dxrufsqktfJL9kZhHb4ggjFYnXXf+bt1Y7/H7gDKRVX1G6tNEVWdxAmov2MBq2jgIx" +
                    "KLnZbo9viLjqHqZHJ0t3+0K8/iFwyJPySan+1bo8CQI3FIJQIDAQAB";
    public static final String privateKeyValue =
            "-----BEGIN PRIVATE KEY-----|"+
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAy9WJJJFS3rH7|"+
                    "AU3fvhYjZvcyC4iT4y5JNKerV/0jexm6UYSI5d99oWIqV5y57Bw8ZvN2vUd5xZ0g|"+
                    "ZBWV+5FjrVbOlHRc4CdcrJwIG3Q266KV+foS0QYrJqhtnxbiTs6dULRnCEuIJPCP|"+
                    "+exWnt2m2SxeyI7et25KaecL6tNXuOcJzOjoRIpxlrM68rQKsHxlgjD/SCsZwMqU|"+
                    "4vIQkLGpFRN1+AolvXo7qm53Gu5+yqS18kv2RmEdviCCMViddd/5u3Vjv8fuAMpF|"+
                    "VfUbq00RVZ3ECai/YwGraOAjEoudluj2+IuOoepkcnS3f7Qrz+IXDIk/JJqf7Vuj|"+
                    "wJAjcUglAgMBAAECggEAHN3IHI8VlS9Tva3Nz5zB6s4NX/hbHC1tLjfMjPqRI8FY|"+
                    "Mk3nRqoIYuKJdKaGiE3iUmbluBcR/xkH9CQYGUs/0wlOkIKow4kqS5VqjUozBdAV|"+
                    "GViCyVNzlX1lxXgG8J51EBfX0v9qc7l4LU5xxOxnaoZkvtJPlegoAstFdULVHvKE|"+
                    "/b7jrTbpprXGudyPOqmR5Mi8tvUR1jPaMV0JfAuAqIEKQC0zAQ1QxxtAUWaoLYf/|"+
                    "ueCpR3XpDCC1X5YGmSzqYn52dSfCJ5yU7+32dfWK/RQuF83uxWsFL1Zf7CyyadqX|"+
                    "OWzEK8gwrnIIwx+Q+8Rtf4JDfh83CT9BWxAzGGfuYQKBgQD2jc2p3reHL6ZNJhq6|"+
                    "TibhtOXl4olu1fS59jSH+d5Tdce9n992MOnBTLRmhjdyXI9enQWYVI9qF3UOLGLR|"+
                    "GjEJeRNQ0b6lpQDVc0AYq/3XyQDmo/IbD8HnMq9/7O7/I61rhhgMHHm10UIVWDnZ|"+
                    "hlFmuSb/blF8RHWYZNv6TTEn9QKBgQDILsa2iTqZvJlkneihj/TUTHAPKta+KYiP|"+
                    "2eJ6tJAK2Gb5bD2RU+1BTbdXONSFTJUrnr0pwqJhYEX64umk7E205u4q3icwn+I2|"+
                    "oVp6fIoYeu0tDH+VAgmTJpgG7twxSxGgS6/kJhxZSrvTqRi+PVyIcGnCGykNXHbz|"+
                    "g++7+f3xcQKBgFouJdKDPve4awh+7nnEih42T3yVLpWWtouqTS6LK1G1m9h0+IQ/|"+
                    "gdCNINL7Np6i0mHV5yz/iPFSISONApvfC56eZX1DKotl3fc0z3X2usNJpwW1Y6GY|"+
                    "UuEgveZ5oDU8NHtGsdcEN1RUdOpfudEhevaqtGPrUuy0EZsrEPbtcxRdAoGBAKVt|"+
                    "unu4ljvcFuuGb2useohDDswJ++K0kg1G4xnCQ9MimJ6A67RApi20WtHyvfXWnuOo|"+
                    "T+zF0skj9VDq2miXe3QG70VvxvUw+5Fn8EyOxNSMKZpz3K84Os9nMnVwSXlW7x8H|"+
                    "zTh+oijMUMIO2MrGDMUYGN328gr/obGGE8TFSC2RAoGBAOt2KFWLbqAeBcwq6oqS|"+
                    "Mdqa8v99AugVHPNdMBzOzDHu+8rGZDiWMNfBD2GjngxmY3WTmGnyD5zZpNXJ3RSC|"+
                    "w0J4IUsUn1VUFyVBKn8O6ydcf/Fnm59lhVKXLi2qK1uxvh+dAvhhlFtf1Ao7j2GM|"+
                    "d2GAJvyhVv0PrFN4mIpH3vei|"
                    +"-----END PRIVATE KEY-----|";

    public static final String NO_SESSION_OR_BRAND_OR_EXP = // with session 'aaaaaa'
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcHAiLCJJRCI6ImlkIiwiVXNlcm5hbWUiOm51bGwsIk" +
                    "JyYW5kIjoibnVsbCIsIlNlc3Npb25JZCI6ImFhYWFhYSIsImlhdCI6MTcyMDYyNTU3NCwibWZhIjpmYWxzZX0." +
                    "BVFdrTB8MxMIHe9P45DshUWuohqy1K08vbegml8aXACkFMyWia4FW1nGk1XmnkJmFFKDGJbQVqZMFd2lkFBYou" +
                    "D3YCPoH0xa6IOt4SXVnpDMo9I-YNVk7eWQcM_LyF9ZKn-DVEmhhVIGs-Ma0FUnONbd8OmemIIMtuSF4ykAO-89" +
                    "rt9jYagmOLrsmBD8OXip9msX1UwXLqERwf8OnYqRkQ4NvzHVWuyRVbKr5jB9QoHC_rwxb8PZ2wtaSAskGeHq81" +
                    "QIZTfa-9m4xDFOChYFmEENW06AdMRoX3U4az3AL7omVRcHnK3bMqr5Ec_ShDs4DcbWoL1WUzmfiBcVvvIn8A";
}
