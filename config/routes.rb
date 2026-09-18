Beskar::Engine.routes.draw do
  # Root route - dashboard
  root to: "dashboard#index"

  # Dashboard
  get "dashboard", to: "dashboard#index", as: :dashboard

  # Security Events
  resources :security_events, only: [:index, :show] do
    collection do
      get "export"
    end
  end

  # Banned IPs
  resources :banned_ips do
    member do
      post "extend"
      get "review"
    end

    collection do
      post "bulk_action"
      get "export"
    end
  end

  resources :administrative_actions, only: [:index, :show]

  # No versioned JSON API is implemented. Authenticated CSV/JSON exports live
  # on the resources above; do not expose routes to nonexistent controllers.
end
