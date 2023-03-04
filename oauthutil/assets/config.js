/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

var config = {
  apiKey: "AIzaSyDGpWIgfbQ756LcyQylCWIN7DwdfYFIotY",
  authDomain: "roboweb-56423.firebaseapp.com",
  projectId: "roboweb-56423",
  storageBucket: "roboweb-56423.appspot.com",
  messagingSenderId: "1052349428368",
  appId: "1:1052349428368:web:870453aea1a464c8cbde15"
};
firebase.initializeApp(config);


// Google OAuth Client ID, needed to support One-tap sign-up.
// Set to null if One-tap sign-up is not supported.
// https://developers.google.com/identity/one-tap/web/get-started
// TODO(jeremy): Login with Google to work even when this is null.
var CLIENT_ID = null;
