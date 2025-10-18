using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;

public static class FirebaseService
{
    // Inicializa FirebaseApp si aún no existe
    public static void Initialize(string serviceAccountPath)
    {
        if (FirebaseApp.DefaultInstance != null) return;

        GoogleCredential credential = GoogleCredential.FromFile(serviceAccountPath);
        FirebaseApp.Create(new AppOptions()
        {
            Credential = credential
        });
    }
}
