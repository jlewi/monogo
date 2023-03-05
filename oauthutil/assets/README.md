# FirebaseUI for web - Auth Demo

Assets contain static assets for creating a firebase login page.
It is based on the [FirebaseUI web](https://github.com/firebase/firebaseui-web/tree/master/demo) demo.
which is accessible here:
[https://fir-ui-demo-84a6c.firebaseapp.com](https://fir-ui-demo-84a6c.firebaseapp.com).


## Integrate One-tap sign-up with FirebaseUI (optional)

If you want to integrate with
[One-tap sign-up](https://developers.google.com/identity/one-tap/web/overview),
you will also need the Google OAuth web client ID corresponding to that project
which can be retrieved from the Google Cloud Console. This value will need to be
populated in `CLIENT_ID`.
The domain of the page has to also be whitelisted. Learn more on how to
[get started with One-tap sign-up](https://developers.google.com/identity/one-tap/web/get-started).
Skip this step, if you don't want to use One-tap sign-up with FirebaseUI.
