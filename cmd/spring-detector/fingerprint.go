// Copyright (c) 2021- Stripe, Inc. (https://stripe.com)
// This code is licensed under MIT license (see LICENSE-MIT for details)

// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

type fingerprint struct {
	file    string
	sha256  string
	version string
}

var springwebfluxArchiveFingerprints = []fingerprint{
  {version: "5.0.0", sha256: "534c2e1bc7c4df900e7aef2e7495d3c1fd2dccc48ac2b8b099ac6b5ed52af852"},
  {version: "5.0.10", sha256: "158e630d388d311c98d3e37dbb09cebbc0edeb9367a95cca8067d65d4c9851ac"},
  {version: "5.0.11", sha256: "b19b1f7544e8bbfb3ecfce2c7831a0dbd70dea1848a176ae5347ed81ee876b49"},
  {version: "5.0.12", sha256: "fdc7e7ff32a4adff933346dd695e97f79bc783ebed613f64590c55fe39aa14be"},
  {version: "5.0.13", sha256: "48331103de2456701d02fbfd1d56a6785e2baf639ea0645ad1365cd66b0a6ac7"},
  {version: "5.0.14", sha256: "1fe397cbca7e4b266253687d89ba7dc766c0677d14f3a320d1e71b16af010b49"},
  {version: "5.0.15", sha256: "8034b05e50e9f1082e16a63345022e3308aada664682908fa8ee7a9bc533d54d"},
  {version: "5.0.16", sha256: "96a6c615ca5b338821362f9b20f73f91b8d82fc53e3ad34625b46277ee0a9308"},
  {version: "5.0.17", sha256: "e1ddc81ceecf0fcc6ea8e9a3d53fe7ef642db84d29ac5b9c448ed0132d8ac32a"},
  {version: "5.0.18", sha256: "b2925a925af93994fced2d6f760002ecf7a977d2066d62b969138d506b5169d8"},
  {version: "5.0.19", sha256: "30fabb1cd0c5f3ca25db4653ba2f443691189f5dbec33fd7115ec1fb832e8b38"},
  {version: "5.0.1", sha256: "5f0c0ff1028e3e5cf207afaba567c174b46c23af0b7c620a06b36d515946caa5"},
  {version: "5.0.20", sha256: "18e02b228e4606ac3c8ed537d6c9947c4e7e6cbfe4675c9d1ee9f251f20e6372"},
  {version: "5.0.2", sha256: "e5711e17b60b4638402cd601be56a5c488cc89d292eb579caaf98314fada5294"},
  {version: "5.0.3", sha256: "af1dc34b00be910d8231dff092c050a6e2a374352a10bd83356a1903bc1ae364"},
  {version: "5.0.4", sha256: "ade08fd3be594522f96507d1704ade1171c4d8a40554ae93560ba1b685f2d563"},
  {version: "5.0.5", sha256: "3dc06daf4a74f6ec05fd01eb036f01e8604695e411c39dbd92a17b4300ca2f2b"},
  {version: "5.0.6", sha256: "760fdd44552d99789a971fa5a55813ef9c5cc4a4ca7dfc449d6f1a58ba2c6fab"},
  {version: "5.0.7", sha256: "ac8e79aeafab4e6d85da2a5939735c81827eeceb58ae83e2e53d0a45c1ecb2d2"},
  {version: "5.0.8", sha256: "853bde1a3ac5afba80a86655a62eb7800e443247b0420488e097a4eadfa29578"},
  {version: "5.0.9", sha256: "bd489b58e512712cf95c919224d448f484967b5c85bfa78ca1d150bc97b2dc4a"},
  {version: "5.1.0", sha256: "74a389a34b15246c356746cd295624e35294742eeefd725b68523b5b5307f655"},
  {version: "5.1.10", sha256: "e9955dfd4800cdda5986bb53bb9d7134be442057f19cb875e6d8732da6a16d87"},
  {version: "5.1.11", sha256: "abefbba441de6d53bfa5ef0e2d673a39bc2559f271d147838a5f2da2008c2504"},
  {version: "5.1.12", sha256: "75382e0da8e27f0d6ddb95905cfbb9c53cd417a837e0af5b6564d4fd52c824a8"},
  {version: "5.1.13", sha256: "6ada93be3c432b26b0c924b3ef097715f5223d2d8827bed967437318a05c108e"},
  {version: "5.1.14", sha256: "4991fe1bcc8f392a40f42f032932c7cf0be8f74f4a8dbd94decc9272870c491d"},
  {version: "5.1.15", sha256: "5129dce97e648a5c6b5ce6f35d64a977bf961aaec6c9350eeecddbfaed8c67d2"},
  {version: "5.1.16", sha256: "481d243b7a44cd10c43a4382293005489dbbceb771f2a8e3f984db14c3edf021"},
  {version: "5.1.17", sha256: "67c894ba9dde383f8600839a7227a96a3ebc301e9a1eec0b92639d1351ab24d6"},
  {version: "5.1.18", sha256: "c91e3b928627fc9b6d0322df3386415ed8f528b9cf207c0b849917ed1e6c3c48"},
  {version: "5.1.19", sha256: "f607d7e1699250fa934134e299a1bade5e54394b14dc3a0093adef7623af99c3"},
  {version: "5.1.1", sha256: "a0f45c517c9aff4d2ec03486903b34d0d9cf99a784220e206add8358c1d21cf2"},
  {version: "5.1.20", sha256: "42c8854930895f3f55b7a28d8ccf7f8475b68e349a4f75f790a91e0d15b3431b"},
  {version: "5.1.2", sha256: "737e64d060b3fc7e8b8626fc79bd0c8f5cef06fb92572fe329816ec64571012f"},
  {version: "5.1.3", sha256: "a47af6ceae9bc0ef114bb33fa2ce173889ede23e209e949496d4c7e56376dd3a"},
  {version: "5.1.4", sha256: "824c85c723e1931caab116668132743cbdbe281ee155dce4b6e4dcfb3d495917"},
  {version: "5.1.5", sha256: "5c853396f1500d0e0deb40284f3b1fd28bc33e97993057e547ef5f0927ef60c7"},
  {version: "5.1.6", sha256: "a13650048057e62b08dbbdd867e53cada14a174a93b20f3f342f15127cbf58fd"},
  {version: "5.1.7", sha256: "c954ed8c89b19d1ce5bc529ea408acaff66d8aa10f1e1de8fefd688198d78668"},
  {version: "5.1.8", sha256: "ba9a5f7c0fe3d71c3dc2954db9a05460eebc92dedaf8dbeb3df217f82a04fa51"},
  {version: "5.1.9", sha256: "04a834bb1f901a122a3b34c6da496cdd9c23d467f71a4a16dc34675fb50dfb18"},
  {version: "5.2.10", sha256: "cbec250391ccc179281864e67acb908824b670044388c9bd0565b61c0a1cf7d6"},
  {version: "5.2.11", sha256: "2e8a83531194c4f389ceabde77d760ab2259487c9b99b34cf8c0e15cba935792"},
  {version: "5.2.12", sha256: "0de7d17cb84a0c8ea4435fba56f4722d8c87c35ff55cae98b995ced8593167d7"},
  {version: "5.2.13", sha256: "8fd76d67090fed5d83fa762fb7460213e2d1e1935988fcb0a67149a99afde179"},
  {version: "5.2.14", sha256: "a8da513839a0c9e20efb0309636d961df845279c38264e1e916bab92435199af"},
  {version: "5.2.15", sha256: "7d99160be243abe7340aec141a03ee9df43716c275ab2e772ef4fde7ee2eb611"},
  {version: "5.2.16", sha256: "9a410b1f992a994f382415526c8aae45b840dabfcf275f087e584eba42669c12"},
  {version: "5.2.17", sha256: "08f7669701b53b007520bf76d4e270f3770401f031fb6adb56f5e19defac2caa"},
  {version: "5.2.18", sha256: "94d9741b95ca174c8b665cd332174427e3060e4e2df0cbe7f0d94f9446254890"},
  {version: "5.2.19", sha256: "00a5c086732d4f27fffabd03a90b9e764143e10845d72c745fcb4b4cca2c2340"},
  {version: "5.2.1", sha256: "c2b3643fc082d033159ef857e029da68ad817750760d39d86f80485ab91d42d5"},
  {version: "5.2.2", sha256: "e92377d9ecf0df52b3602c3490ec7000c6043c3c936530c791cc0496672728b6"},
  {version: "5.2.3", sha256: "db245cde0c96af51916d5e4494c2401fa7df7174f652b401a891314296f405cd"},
  {version: "5.2.4", sha256: "d4fcf537690647e2c86d2981fc6fa0783a0c079ec5a9c3d66d2ff31575ee24b3"},
  {version: "5.2.5", sha256: "49d30c29191eb0494811bb4ddff69a0cf79f8eac2d57c6928fafdd70ed773ba8"},
  {version: "5.2.6", sha256: "fbc11f79d441be0eb084c7ee433e76060f4549a32b38244d957b6638a34cbe72"},
  {version: "5.2.7", sha256: "c8421d207500b16886ec3bf83796309a112d1ccc3814883f7006b89c82499c93"},
  {version: "5.2.8", sha256: "45cbf88f54040a968b79e24531e9f2bdf3d7f7e83ea6148672e1d9c81dabcffd"},
  {version: "5.2.9", sha256: "c73510968ac3f79c1c8cc881120b37045fae0504c51a15b8aa2afcf33831fd65"},
  {version: "5.3.10", sha256: "54ad96ac3cb6731e627be241fdda708e2e7f903ec47d1ce21d11960a39065745"},
  {version: "5.3.11", sha256: "8089f8becd67dc6d836f1fd2d82c48f6023c0ad19ac267da32c5cb36e0640b1e"},
  {version: "5.3.12", sha256: "cffae1c3188c86c58d5a2aeaf680c7b197f2445d00373977f6ac44011a01df0f"},
  {version: "5.3.13", sha256: "a003c78814fd0fb80a83e27aa4fd5740d332d35150778cefac3fd3b3a7dd3845"},
  {version: "5.3.14", sha256: "8ca0acc4e578231e23ea36acc2b6bfbb51e63751f81977a3875dda2a70513e1a"},
  {version: "5.3.15", sha256: "5e1420efdee18541aa66169bbd155a7d189c67e45b2d7f74e2fe4654c03bc63b"},
  {version: "5.3.16", sha256: "ccc9a8bfb4c7cd286bb50be3d828c3cb2a845da4df79b49cfed9ba64ffe4a8dd"},
  {version: "5.3.17", sha256: "985c75d219c492a8b7ac5a8bb8c0dacebc31ef9cf95597270165a3e29547419f"},
  {version: "5.3.1", sha256: "ee0bf235d766d4e60cdcfc68552781b309cfa6f1b9ef385024b3ab51bdb28658"},
  {version: "5.3.2", sha256: "8f1b2c2fe77454adf065938fbf70d622a040e69ed9a00ad6d4c3298eb71e72cf"},
  {version: "5.3.3", sha256: "0c5647117ffc23e9b3654947d9dcb75e9e4113fe18aae9fc29f9ccc66ea10c60"},
  {version: "5.3.4", sha256: "8b419550a6972a701a60a6d4934b3e93c931ade7f11d16889222381c789b3da8"},
  {version: "5.3.5", sha256: "eaedbf545e8a915cb0199ba7250cfc0a8440954882c13fef7686fc5e8ec8d67d"},
  {version: "5.3.6", sha256: "4c03bdbcd9af361e065277b387d6570a8660f8528abb657435f157c86eeb65ae"},
  {version: "5.3.7", sha256: "de16cae39fc62c38cf1d08e083b85d131f0e103ad6f51e48638362a344d2ed85"},
  {version: "5.3.8", sha256: "00deae47755c4592a783839a4158fd60e2c781dcfa2b631f9dfc2ea1c82749ff"},
  {version: "5.3.9", sha256: "20137bddfb5bd3244cfd7d9c431b68a55baf2c2a1ae72e2aee784e84613fe2d2"},
}

// JAR fingerprints from archive.apache.org and repo1.maven.org
var springmvcArchiveFingerprints = []fingerprint{
  {version: "4.3.10", sha256: "c571f9f34874f01722447a23e24bf0237bbbd81e9bf68069fbfed932681168b2"},
  {version: "4.3.11", sha256: "22880c45d29205c8956e0a4870014974fa70eed5d9a8c3b911ec14b570fddc3d"},
  {version: "4.3.12", sha256: "200d76f7305baf5f33e9f3244a66b6ce3f78f0387f5b8ca0b190c4d317e1fd06"},
  {version: "4.3.13", sha256: "d0959efc8571b500e32dc2e16a850ba009c5f701b52f06d3bdb0f23a3c2fe409"},
  {version: "4.3.14", sha256: "01f4eceae4568feb4776b78554e72774480fe52f28d2d64d777796be6e1f4dfc"},
  {version: "4.3.15", sha256: "2ad61a5b6c0c8dc83f3ef4f3e5451cedc12bb24b113834290d948e6bc8942f0e"},
  {version: "4.3.16", sha256: "fa820188ab35b6cbb9c4bc220c0e6336ad05e9a27f54791c642334533b2155fe"},
  {version: "4.3.17", sha256: "19a48ec62bbad4e3a9116c6cf4ea49c43c3cb08048a66a317c419e67ad8f5d86"},
  {version: "4.3.18", sha256: "08f43744a1ea6eab11b26290dd09a01f04e09448ac0fa79442ae49b9d042fe93"},
  {version: "4.3.19", sha256: "2ebd2137494fa3fdb0f0e34014027c1346490e7a9fbbcc70e9fa3df8921fb7e3"},
  {version: "4.3.1", sha256: "13f39973732d0c6b536a6a7154a768d58bb838d73dc1c31b67376b35a8fc2f4a"},
  {version: "4.3.20", sha256: "ba8e70ba8d93404b8a267171dc7b232866c87a06a00fb3b2427d5d40dab13a5d"},
  {version: "4.3.21", sha256: "aeb5b0d7f45cdfd5ecf941f3264eb8e55ac7176e3744f01a0d826e58eb817c73"},
  {version: "4.3.22", sha256: "f1176037c9c60aef9eae742261d375180dc91e43d621660b9f1e3e2e8e5bf56c"},
  {version: "4.3.23", sha256: "f3993ee37fb7fab9d1561f18f7efc8470e2d73f61cdaec8a070e4a1f70195170"},
  {version: "4.3.24", sha256: "359419fc07d45fcba0451cadd77f7bf50504cdab9de32b865290e0b19e5f1bb5"},
  {version: "4.3.25", sha256: "0cdf173ebcd84f8e4edced45494c109077d90800707de8fa704dd5e376de0339"},
  {version: "4.3.26", sha256: "d9d956555fa01b3969d0ca60b730c25f9162aa950995d76a1f8407adc6caf75c"},
  {version: "4.3.27", sha256: "2ef25a3b394950de236dd4ad96defd1ea91fb5907d15ece0a1d7c96620233a36"},
  {version: "4.3.28", sha256: "26b4b28f9129c10c7b4c58cbd759f21241190a01a4429235bddb90128671d434"},
  {version: "4.3.29", sha256: "5f283b494b9eeff87c05b5321980d40789b160aed012aa4c47e20d48e4edcaba"},
  {version: "4.3.2", sha256: "f0a08cfb9fadf6e50f273770947dd0b9cc437413c147c3b8db2b0b40bc43a09c"},
  {version: "4.3.30", sha256: "bde2a2407dc92dc4bb29b1394c9b2996d77ea27044df9fce7214b4abd0099bdf"},
  {version: "4.3.3", sha256: "aaf64539b560ba27077cd7722016dca7b5d7efb8292ccc0df23ad12ae0815365"},
  {version: "4.3.4", sha256: "f3aa1ebc57a5be69f0a0de468e7d3caf3bbccdb9bff6caf04ea1892d8a8ce7fa"},
  {version: "4.3.5", sha256: "aae43f0dbaad48599e4bddcc5fc38656b0a25c47f146bde2b304d4706ff44f26"},
  {version: "4.3.6", sha256: "5938eae0e70bb383292bbbeed011e3b613f63a9e3c249b24b5df23e7ca4f2822"},
  {version: "4.3.7", sha256: "542c118dd2f767095a5d9e6d9298753d69e64f5be8b318673c993e9db9e1fb57"},
  {version: "4.3.8", sha256: "7db3c12c160e862a2115277a365cc3c88093c9b17a6f8559de002bf64fe89003"},
  {version: "4.3.9", sha256: "8dc2a998995899df70b3c791c858c6e1521ece192a91b08bf390e79b717682a1"},
  {version: "5.0.0", sha256: "8ee645fe07d21a1357744c9f73a1f380da80801badfbbf52344147791dad2b96"},
  {version: "5.0.10", sha256: "e55751061b496106777739938c89c1eca943d962db76fb149b5cb9303ec72e54"},
  {version: "5.0.11", sha256: "214156e8ef74f702487ea8f2665f1e48700bcc2289b49f8bc92a9c2d4f89dd6c"},
  {version: "5.0.12", sha256: "3cefa0f94aba631e4d3e399993eb02fdddbc8ef74f0b2bf0a40562b481861b2a"},
  {version: "5.0.13", sha256: "11b92c8c32a9f474c124e72309e89a7195fa2b97a2d9772444ee47d2dae10b94"},
  {version: "5.0.14", sha256: "1ba3c47d14164a385c6b6b937ba73c8ff6e50baa33c8313bc2b3423a76810b1b"},
  {version: "5.0.15", sha256: "db8ca6932aef51ae1eb7a6d6e4a334792004ef5ac10c0aa84028415d9753991c"},
  {version: "5.0.16", sha256: "d57503a208c26870cd50816c0e4c0c898318c406622902c8d98d95f6701a6bac"},
  {version: "5.0.17", sha256: "cb7c701dd0d0e56fceb7fde5d41ff2e08c92d3b866baaacf6b9649da96cb8628"},
  {version: "5.0.18", sha256: "fcd2dd3117f38466c37cf85eaa462b70eda0448725bfc7c3b9041e22ad73e4f5"},
  {version: "5.0.19", sha256: "50b957a158569fc4f91df59188ab0ad124b9eb23f2ed66e639da66145abd03d4"},
  {version: "5.0.1", sha256: "d1920665ec9a3b5f82a7d9bfd06f0357d4da407485b30acfdb973012f2219c51"},
  {version: "5.0.20", sha256: "2fc4289ab0a66d5ec6e336284dd45f7a90c53d0e115618fb1eab801780940a3d"},
  {version: "5.0.2", sha256: "bed5fad6f46047aa5e5953885ddfb5cb6c122b9fbac763189502045b38e44e76"},
  {version: "5.0.3", sha256: "071a95d63cc6d7ea1cb62c368146d97559118322efdfa33a8e15da8987a11fa6"},
  {version: "5.0.4", sha256: "825e6236633b82879f8d10da31816688f8e92be72c343595a126b78be24a8f80"},
  {version: "5.0.5", sha256: "9898bb0d8f3109434afc0e92754cc867ac6963227e9ca0100b7e4f2bf11a5658"},
  {version: "5.0.6", sha256: "e09a862bd3b54e780e4d5d997c8c00cb474ccaa4f5e8c8cee5fef4f4ad0208f0"},
  {version: "5.0.7", sha256: "7cecfb40dcfcae8681ca96ddc286e0b2901426db4b91fbf01f372f7689f7bc95"},
  {version: "5.0.8", sha256: "6966ef3b603d641809b06da7e7eeadbfb37238a20216541b15a533ce62f02d2d"},
  {version: "5.0.9", sha256: "dc1a0677b717d2711da931c381392342dc66ffea5b2004288c3944de5480b8de"},
  {version: "5.1.0", sha256: "03a76c6fb484eeec91acc53b7839324b0a6d2ac59cccba386548909cef6074ff"},
  {version: "5.1.10", sha256: "622955e52bb3affbdd66c175730c918c1ad43fd53da98dd4987154b4295ed0f8"},
  {version: "5.1.11", sha256: "30d50b0cd60b50f6e2b2a1c1e5a62d7800991046ad57afe107f7b24078b043fd"},
  {version: "5.1.12", sha256: "1e9b1ab7bee4ba81de640feb85275cccd214d43f493c21a04c4b3d759692a700"},
  {version: "5.1.13", sha256: "e3da7b4f274c15b71f622f4c956c2009b548719fdc109fe8732ca92e63f22a5f"},
  {version: "5.1.14", sha256: "df094d490a52a0a2c55d29ef7b3daf06d279bdd43bdb2254db5b013b8ccd7fb3"},
  {version: "5.1.15", sha256: "3943b76ea2ebcaec4c7ea732490da59eaa10e3bf64d590511e4ca04131aaa9ab"},
  {version: "5.1.16", sha256: "3b00d29d1406b92ff86c534f84ef486ecf71ef7698be29aa9dd1b0cbbfca2f56"},
  {version: "5.1.17", sha256: "3a53c37dda57e5c4303f2cc049f3c72a5edf03d5f97ea96760c3927d0259a9cd"},
  {version: "5.1.18", sha256: "d4ee0917a823f2f4f35c8e156a86dbbf4ee013419b72799f97f089c6b6edc2af"},
  {version: "5.1.19", sha256: "a2f7896c48b655bf29c39eaf3300b348c1c6e37037258858dcdedecf1ef24c86"},
  {version: "5.1.1", sha256: "0ff6274d2537c7e52d3be61445ec7e204a511de61cd0d5c93ab03dd717d69cd5"},
  {version: "5.1.20", sha256: "b10e99417618d753170a665909d9baae0507158e0421a5b63f370d30fad2d171"},
  {version: "5.1.2", sha256: "8da6ebe54db7ebe65e35ad455a56c462afc808664157736d449a384614e08d46"},
  {version: "5.1.3", sha256: "197f872b5589c156af033a35dba506d4040040a36bbfcdb6cb7f83cada5799e4"},
  {version: "5.1.4", sha256: "389292b01b5752cba740078bd60ff821f603b0fb972f3659e0afac6c3949058b"},
  {version: "5.1.5", sha256: "7953dc786a5ee32a267cdf8e9be08b94f7cb52bf88dd9752e29ba17943884eb7"},
  {version: "5.1.6", sha256: "fce541453c977559cbce2a67ed7aa4515092c07fee5569cfac64d022450a91db"},
  {version: "5.1.7", sha256: "90309b44bafb8a7a443d456bdc77e63e03256ea46d056ca70187627b6cb3757f"},
  {version: "5.1.8", sha256: "a367da41eecd3313d6f3f5b60f9d041ee141388a9b7d41089d5fcd05cf7a415e"},
  {version: "5.1.9", sha256: "bd38c37f2acdca11934e6e515d8c7605ff97634cdc908eb9c82a771725aef438"},
  {version: "5.2.10", sha256: "419e7271240f034a47db76c6ae6b5baf57fbc399b7e0f6a5139644a0d6d3ca99"},
  {version: "5.2.11", sha256: "105335f6c15d8f83291a15d55243f26470378b702a88e1ba1d888fcb4bed8dc4"},
  {version: "5.2.12", sha256: "41165487bbc339ae880906039b534e8a50cbd98e868a0c6be758fe249f186f0c"},
  {version: "5.2.13", sha256: "82101df5d115f9bd200a5981b812e3e070ddb4d2d6870ca7d918263390015045"},
  {version: "5.2.14", sha256: "34e85bd9a07f6548d08c59ea3cc6be62120481ac13d2fe3fbaf21ecf7fa97eef"},
  {version: "5.2.15", sha256: "19c9c7ebbbcde7eda22ecf2120dfe087c4ebcf68facda2e16c4bff696e7380b0"},
  {version: "5.2.16", sha256: "cd06736b3a28248d0cd9cffe8463eb4a17ec6b210dc8637e5e52f571303cbab3"},
  {version: "5.2.17", sha256: "b9e0dd567409e912bbddd6bea7e59723e36382e20f914b80f53a84ae0598b785"},
  {version: "5.2.18", sha256: "a602e36f994f0c61890b0117a7894159785dc40656383c33f85abd256ffcfae2"},
  {version: "5.2.19", sha256: "c30c5d66f28333f93851415fd88db44f3406f185d89917ad159707d15ae68710"},
  {version: "5.2.1", sha256: "6a85dc21f75e1d14d7c2135b7c21cdd840eee3577aab5db4981a9507d4eeb119"},
  {version: "5.2.2", sha256: "e3da078986c603697551349f84c062c0322d7a564a2f4cddf8fcf324ebbd6a08"},
  {version: "5.2.3", sha256: "b3b0a2477e67b050dd5c08dc96e76db5950cbccba075e782c24f73eda49a0160"},
  {version: "5.2.4", sha256: "d664b766b89e628f282f8e8c89c7569994f78ec8ee59f3a0b063b813ff0215a9"},
  {version: "5.2.5", sha256: "2b36f6f96e6f2e5102bc624e74b0f139ad064cfd1a7945b2e82f62bd70d78ada"},
  {version: "5.2.6", sha256: "bfcf0312998a4fb1f69d6a044dfd13e49d72b233caf0347c7df76db6f3223369"},
  {version: "5.2.7", sha256: "0682b1943588fce2aacf84f9c295bf6ebc784dc8e5a1888d5de52787d9581926"},
  {version: "5.2.8", sha256: "4d1e85964f1ee339e9a9b0244163a2f2cc37f1eeb09317c9313e2678a13ac20c"},
  {version: "5.2.9", sha256: "2825194d46c244ff5e64fcba9273bfc8779667a3aac33eb4ea9ef87dfb4fa4ac"},
  {version: "5.3.10", sha256: "de009be08ca86f3ebfe2d3a8462cf9cc005011ffa9f5e47222467bb353ba0c68"},
  {version: "5.3.11", sha256: "7dc479df68caf213df4c9315263290d21eb2b866142b19fed0be891507d2ad5d"},
  {version: "5.3.12", sha256: "d6c6567c04ebfcc9605dfe105817427eda3d8583b98c32b6a4eed802da843836"},
  {version: "5.3.13", sha256: "869f7c868b56fe46dd9446f27271d8804db8daf279952ef0b7e7fd97411cf359"},
  {version: "5.3.14", sha256: "68a7414375783e9dd51f477df2f8aceee71f47153278c9cb005cf8304b9b6858"},
  {version: "5.3.15", sha256: "77ee2f3d7ff5eef47e15937033de6c478c84bb40a3b90405645f03780dcd9fe1"},
  {version: "5.3.16", sha256: "197620fa85ba4eb8881efadafaa3ff93934597b28eee2904870a4aa72eb044ba"},
  {version: "5.3.17", sha256: "6cf77c887c3a683659466c6b33f41e296f3e4ed79e091cc214eba247fc1fcaec"},
  {version: "5.3.1", sha256: "565b5e4503a4a427bd46520a432e39233b1d93d307c85d050afa29904b7e836b"},
  {version: "5.3.2", sha256: "5eb80a5c86d5c97b0ede61dfa62a74cc38272434cd13dcdf9e048a7d586792f5"},
  {version: "5.3.3", sha256: "fcd8d74bb1edc8d7c6c9291fa6008a5810b4ecfe4f4f0e2b9d886428b4a29966"},
  {version: "5.3.4", sha256: "fb6ae8aa957d4b9e4648dc3a36876f34edf8634715680fbbb566242fc489a63b"},
  {version: "5.3.5", sha256: "d663076cf51140e4a5a489cf6eced2af2457531a75d9cbf6ffb658b7be9d4099"},
  {version: "5.3.6", sha256: "0a166d4fb7651acede3db2e47a77048355b4a7fa02b292a2a58a046c11a54775"},
  {version: "5.3.7", sha256: "5989fdb8cfcfb0fe36ca45cdb55db2caab37d197e1c3ca5a341f7cb2a23845d8"},
  {version: "5.3.8", sha256: "05f6d0e32586af83a1ff2c4d98d98afd2882f006752067028b453b20e46e0a2c"},
  {version: "5.3.9", sha256: "ab3152e8dea26ff84c0d3a270c4f65ae56877bb198fd38dfe4e7368cc9b8df7b"},
}

// unique class fingerprints from archive.apache.org and repo1.maven.org
var springmvcFingerprints = []fingerprint{
	// xx-core-2.0-alpha1.jar 28
	{version: "2.0-alpha1", sha256: "179bc91a6bdb353bad64408d3f14976a4b81f916f76e45ce48a76dc1bf5d37e4", file: "org/apache/logging/log4j/core/config/XMLConfiguration.class"},
	{version: "2.9.1", sha256: "fd9f904c9c628cd5a85715031d4682c680d092ee7e5455aaf8a482206822d213", file: "org/apache/logging/log4j/core/tools/picocli/CommandLine$Help$Ansi.class"},
}

// unique class fingerprints from archive.apache.org and repo1.maven.org
var springwebfluxFingerprints = []fingerprint{
	// xx-core-2.0-alpha1.jar 28
	{version: "2.0-alpha1", sha256: "179bc91a6bdb353bad64408d3f14976a4b81f916f76e45ce48a76dc1bf5d37e4", file: "org/apache/logging/log4j/core/config/XMLConfiguration.class"},
	{version: "2.9.1", sha256: "fd9f904c9c628cd5a85715031d4682c680d092ee7e5455aaf8a482206822d213", file: "org/apache/logging/log4j/core/tools/picocli/CommandLine$Help$Ansi.class"},
}