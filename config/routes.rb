Rails.application.routes.draw do
  devise_for :users

  mount Rswag::Ui::Engine => "/api-docs"
  mount Rswag::Api::Engine => "/api-docs"

  resources :sightings, only: %i[index show]

  namespace :api do
    namespace :v1 do
      resources :sightings, only: %i[index show]
      resources :shapes, only: :index
    end
  end

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Letter opener for development email preview
  if Rails.env.development?
    mount LetterOpenerWeb::Engine, at: "/letter_opener"
  end

  root "home#index"
end
