import { fireEvent, render, screen } from '@testing-library/react'

import App from './App'

describe('<App />', () => {
  it('should render the App', async () => {
    render(<App />)

    // Heading
    expect(
      await screen.findByRole('heading', {
        name: /Configure Guard/i,
        level: 1
      })
    ).toBeInTheDocument()

    // Base URL input present
    const baseUrlInput = screen.getByTestId('base-url-input') as HTMLInputElement
    expect(baseUrlInput).toBeInTheDocument()

    // Provide a base URL so advanced settings render the select
    fireEvent.change(baseUrlInput, { target: { value: 'http://localhost:8080' } })

    // Toggle advanced setup to reveal auth mode select
    screen.getByTestId('setup-settings-toggle').click()
    expect(await screen.findByTestId('auth-mode-select')).toBeInTheDocument()

    // Save button becomes enabled once base URL is provided
    const saveBtn = screen.getByTestId('save-config') as HTMLButtonElement
    expect(saveBtn).toBeInTheDocument()
    expect(saveBtn.disabled).toBe(false)
  })
})
