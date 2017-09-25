class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  # You should configure your model like this:
  # devise :omniauthable, omniauth_providers: [:twitter]

  # You should also create an action method in this controller like this:
  # def twitter
  # end

  # More info at:
  # https://github.com/plataformatec/devise#omniauth

  # GET|POST /resource/auth/twitter
  # def passthru
  #   super
  # end

  # GET|POST /users/auth/twitter/callback
  # def failure
  #   super
  # end

  # protected

  # The path used when OmniAuth fails
  # def after_omniauth_failure_path_for(scope)
  #   super(scope)
  # end
  def all
    user = User.from_omniauth(request.env["omniauth.auth"])
    if user.persisted?
      session[:user_id] = user.id
      sign_in_and_redirect user, notice: "Signed in!"
    else
      # Devise allow us to save the attributes eventhough
      # we havent create the user account yet
      session["devise.user_attributes"] = user.attributes
      # Because Twitter doesn't provide user's email, it would be nice if we force user to enter it
      # manually on the registration page before we create their account.
      # Here we pass the callback parameter so that we could use it to edit the registration page.
      redirect_to new_user_registration_url
    end
  end

  alias_method :microsoft_live, :all
end
